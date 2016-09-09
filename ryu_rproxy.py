import socket
import struct
import ryu.app.wsgi
import ryu.app.ofctl.api as api
import ryu.cfg
import ryu.lib.hub
import ryu.base.app_manager
import ryu.controller.dpset as dpset

from webob import Response
from ryu.app.wsgi import route
from ryu.ofproto.ofproto_parser import MsgBase
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER

api_expect = dict([
	("OFPEchoRequest", "OFPEchoReply"),
	("OFPFeaturesRequest", "OFPSwitchFeatures"),
	("OFPGetConfigRequest", "OFPGetConfigReply"),
	("OFPBarrierRequest", "OFPBarrierReply"),
	("OFPQueueGetConfigRequest", "OFPQueueGetConfigReply"),
	("OFPRoleRequest", "OFPRoleReply"),
	("OFPGetAsyncRequest", "OFPGetAsyncReply"),
])

class RProxyHttp(ryu.app.wsgi.ControllerBase):
	def __init__(self, req, link, data, **config):
		super(RProxyHttp, self).__init__(req, link, data, **config)
		self.app = data

	@route("list_rproxy", "/rproxy")
	def list_rproxy(self, req, **kwargs):
		data = []
		for dpid,sockname in self.app.accepting_sockets.items():
			data.append(dict(
				datapath_id=dpid,
				datapath_hex="0x%x" % dpid,
				sockname=sockname))
		
		return Response(json=data)
	
	@route("op_rproxy", "/rproxy/{dpid}")
	def op_rproxy(self, req, dpid, **kwargs):
		if dpid.lower().startswith("0x"):
			dpid = int(dpid, 16)
		else:
			dpid = int(dpid)
		
		if "up" in req.params:
			if self.app.accepting_sockets[dpid] is None:
				self.app.setup_rproxy(dpid)
		elif "down" in req.params:
			self.app.shutdown_rproxy(dpid)
		
		return Response(json=dict(
			datapath_id=dpid,
			datapath_hex="0x%x" % dpid,
			sockname=self.app.accepting_sockets[dpid]))


class RProxy(ryu.base.app_manager.RyuApp):
	_CONTEXTS = {
		"wsgi": ryu.app.wsgi.WSGIApplication,
		"dpset": dpset.DPSet,
	}

	def __init__(self, *args, **kwargs):
		super(RProxy, self).__init__(*args, **kwargs)
		kwargs["wsgi"].register(RProxyHttp, self)
		self.dpset = kwargs["dpset"]
		self.CONF.register_opts([
			ryu.cfg.BoolOpt("rproxy_auto", default=True, help="automatically open proxy socket"),
			ryu.cfg.IntOpt("rproxy_socket_backlog", default=2, help="proxy socket listen arg"),
			ryu.cfg.StrOpt("rproxy_addr", default="", help="proxy socket listen arg")
		])
		self.accepting_sockets = {} # datapath_id => listening socket

	@set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
	def prepare_rproxy(self, ev):
		if ev.enter:
			if self.CONF.rproxy_auto:
				self.setup_rproxy(ev.dp.id)
		else:
			self.shutdown_rproxy(ev.dp.id)

	def setup_rproxy(self, dpid):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind((self.CONF.rproxy_addr, 0))
		sock.listen(self.CONF.rproxy_socket_backlog)
		self.accepting_sockets[dpid] = sock.getsockname()
		ryu.lib.hub.spawn(self.rproxy, dpid, sock)

	def shutdown_rproxy(self, dpid):
		dp = self.dpset.get(dpid)
		self.accepting_sockets[dpid] = None

	def rproxy(self, dpid, sock):
		sock.settimeout(3)
		ths = []
		while self.accepting_sockets[dpid]:
			try:
				con, addr = sock.accept()
				ths.append(ryu.lib.hub.spawn(self.rhandle, dpid, con))
			except:
				continue
		
		sock.close()
		ryu.lib.hub.joinall(ths)

	def rhandle(self, dpid, sock):
		datapath = self.dpset.get(dpid)
		msg_cls = dict()
		stats_cls = dict()
		for name in dir(datapath.ofproto_parser):
			t = getattr(datapath.ofproto_parser, name)
			if type(t)==type and issubclass(t, MsgBase) and hasattr(t, "cls_msg_type"):
				if hasattr(t, "cls_stats_type"):
					stats_cls[name] = t
				else:
					msg_cls[name] = t
		
		barrier = msg_cls.get("OFPBarrierRequest")
		
		xid = 0
		sock.send(struct.pack("!BBHI", datapath.ofproto.OFP_VERSION, 0, 8, 1))
		while self.accepting_sockets[dpid]:
			pmsg = sock.recv(8)
			if not pmsg:
				break
			phdr = struct.unpack("!BBHI", pmsg)
			if phdr[2] > 8:
				pmsg = pmsg + sock.recv(phdr[2]-8)
			
			if phdr[1] == 0:
				continue # skip hello
			
			if barrier and barrier.cls_msg_type==phdr[1]:
				# api wants to handle barrier
				rmsg = struct.pack("!BBHI", phdr[0], msg_cls["OFPBarrierReply"].cls_msg_type, 8, phdr[3])
				sock.send(rmsg)
				continue
			
			reply_cls = None
			reply_multi = False
			for cls in stats_cls.values():
				if phdr[1] == cls.cls_msg_type:
					reply_multi = True
					break
			
			if reply_multi:
				stats_type = struct.unpack_from("!H", pmsg, 8)[0]
				for cls in stats_cls.values():
					if cls.cls_stats_type != stats_type:
						continue
					if cls.cls_msg_type == phdr[1]:
						continue
					reply_cls = cls
					break
			else:
				for name, req in msg_cls.items():
					if req.cls_msg_type == phdr[1]:
						rname = api_expect.get(name)
						if rname:
							reply_cls = msg_cls[rname]
			
			rmsgs = api.send_msg(self, RawMsg(self.dpset.get(dpid), pmsg),
					reply_cls=reply_cls,
					reply_multi=reply_multi)
			if reply_multi:
				for r in rmsgs:
					h = struct.unpack_from("!BBHI", r.buf)
					sock.send(struct.pack("!BBHI", h[0], h[1], h[2], phdr[3])+r.buf[8:])
			elif rmsgs:
				h = struct.unpack_from("!BBHI", rmsgs.buf)
				sock.send(struct.pack("!BBHI", h[0], h[1], h[2], phdr[3])+rmsgs.buf[8:])
		
		sock.close()

class RawMsg(MsgBase):
	def __init__(self, datapath, buf):
		super(RawMsg, self).__init__(datapath)
		self.buf = buf

	def set_xid(self, xid):
		super(RawMsg, self).set_xid(xid)
		hdr = list(struct.unpack_from("!BBHI", self.buf))
		hdr[3] = xid
		self.buf = struct.pack("!BBHI", *hdr) + self.buf[8:]

	def serialize(self):
		pass
