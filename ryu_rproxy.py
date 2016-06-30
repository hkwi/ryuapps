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
		for dpid,sock in self.app.accepting_sockets.items():
			if sock:
				data.append(dict(
					datapath_id=dpid,
					datapath_hex="0x%x" % dpid,
					sockname=sock.getsockname()))
		
		return Response(json=data)


class RProxy(ryu.base.app_manager.RyuApp):
	_CONTEXTS = {
		"wsgi": ryu.app.wsgi.WSGIApplication,
	}

	def __init__(self, *args, **kwargs):
		super(RProxy, self).__init__(*args, **kwargs)
		kwargs["wsgi"].register(RProxyHttp, self)
		self.CONF.register_opts([
			ryu.cfg.IntOpt("rproxy_socket_backlog", default=2, help="proxy socket listen arg"),
			ryu.cfg.StrOpt("rproxy_addr", default="", help="proxy socket listen arg")
		])
		self.accepting_sockets = {} # datapath_id => running(bool)

	@set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
	def setup_proxy(self, ev):
		if ev.enter:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.bind((self.CONF.rproxy_addr, 0))
			s.listen(self.CONF.rproxy_socket_backlog)
			self.accepting_sockets[ev.dp.id] = s
			ryu.lib.hub.spawn(self.rproxy, ev.dp, s)
		else:
			self.accepting_sockets[ev.dp.id] = None

	def rproxy(self, datapath, sock):
		ths = []
		while self.accepting_sockets[datapath.id]:
			con, addr = sock.accept()
			ths.append(ryu.lib.hub.spawn(self.rhandle, datapath, con))
		
		s.close()
		ryu.lib.hub.joinall(ths)
		delete(self.activation[datapath.id])

	def rhandle(self, datapath, sock):
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
		while self.accepting_sockets[datapath.id]:
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
			
			rmsgs = api.send_msg(self, RawMsg(datapath, pmsg),
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
