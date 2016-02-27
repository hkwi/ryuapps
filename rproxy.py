import socket
import struct
import ryu.app.wsgi
import ryu.app.ofctl.api as api
import ryu.cfg
import ryu.lib.hub
import ryu.base.app_manager
import ryu.controller.dpset as dpset

from webob import Response
from webob.exc import *

from ryu.app.wsgi import route
from ryu.ofproto.ofproto_parser import MsgBase
from ryu.ofproto import *
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER

api_expect = dict([
	(ofproto_v1_3_parser.OFPEchoRequest, ofproto_v1_3_parser.OFPEchoReply),
	(ofproto_v1_3_parser.OFPFeaturesRequest, ofproto_v1_3_parser.OFPSwitchFeatures),
	(ofproto_v1_3_parser.OFPGetConfigRequest, ofproto_v1_3_parser.OFPGetConfigReply),
	(ofproto_v1_3_parser.OFPBarrierRequest, ofproto_v1_3_parser.OFPBarrierReply),
	(ofproto_v1_3_parser.OFPQueueGetConfigRequest, ofproto_v1_3_parser.OFPQueueGetConfigReply),
	(ofproto_v1_3_parser.OFPRoleRequest, ofproto_v1_3_parser.OFPRoleReply),
	(ofproto_v1_3_parser.OFPGetAsyncRequest, ofproto_v1_3_parser.OFPGetAsyncReply),
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
					datapath_hex=hex(dpid),
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
		cls_list = []
		stats_list = []
		for name in dir(datapath.ofproto_parser):
			t = getattr(datapath.ofproto_parser, name)
			if type(t)==type and issubclass(t, MsgBase) and hasattr(t, "cls_msg_type"):
				if hasattr(t, "cls_stats_type"):
					stats_list.append(t)
				else:
					cls_list.append(t)
		
		barrier_cls = [None, None]
		if "OFPBarrierRequest" in dir(datapath.ofproto_parser):
			barrier_cls[0] = getattr(datapath.ofproto_parser, "OFPBarrierRequest")
		if "OFPBarrierReply" in dir(datapath.ofproto_parser):
			barrier_cls[1] = getattr(datapath.ofproto_parser, "OFPBarrierReply")
		
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
			
			if barrier_cls[0] and phdr[1]==barrier_cls[0].cls_msg_type:
				# api wants to handle barrier
				rmsg = struct.pack("!BBHI", phdr[0], barrier_cls[1].cls_msg_type, 8, phdr[3])
				sock.send(rmsg)
				continue
			
			is_multi = False
			reply_cls = None
			reply_multi = False
			for cls in stats_list:
				if phdr[1] == cls.cls_msg_type:
					is_multi = True
					break
			
			if is_multi:
				stats_type = struct.unpack_from("!H", pmsg, 8)[0]
				for cls in stats_list:
					if cls.cls_stats_type != stats_type:
						continue
					reply_multi = True
					if cls.cls_msg_type == phdr[1]:
						continue
					reply_cls = cls
					break
			else:
				for req in cls_list:
					if req.cls_msg_type == phdr[1]:
						reply_cls = api_expect.get(req)
			
			rmsgs = api.send_msg(self, RawMsg(datapath, pmsg),
					reply_cls=reply_cls,
					reply_multi=reply_multi)
			if is_multi:
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
