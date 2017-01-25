import struct
import ryu.base.app_manager
from ryu.app.ofctl import api
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_parser import MsgBase

api_expect = dict([
	("OFPEchoRequest", "OFPEchoReply"),
	("OFPFeaturesRequest", "OFPSwitchFeatures"),
	("OFPGetConfigRequest", "OFPGetConfigReply"),
	("OFPBarrierRequest", "OFPBarrierReply"),
	("OFPQueueGetConfigRequest", "OFPQueueGetConfigReply"),
	("OFPRoleRequest", "OFPRoleReply"),
	("OFPGetAsyncRequest", "OFPGetAsyncReply"),
])


def send_msg(app, datapath, buf):
	'''
	send a binary openflow message
	@return same as ryu.app.ofctl.api.send_msg
	
	useful with ofpstr, for example
	
	class X(ryu.base.app_manager.RyuApp):
		@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
		def on_switch_ready(self, ev):
			rule="in_port=1,@apply,output=2"
			send_bin(self, ev.msg.datapath, ofpstr.ofp4.str2mod(rule))
	'''
	msg_cls = dict()
	stats_cls = dict()
	for name in dir(datapath.ofproto_parser):
		t = getattr(datapath.ofproto_parser, name)
		if type(t)==type and issubclass(t, MsgBase) and hasattr(t, "cls_msg_type"):
			if hasattr(t, "cls_stats_type"):
				stats_cls[name] = t
			else:
				msg_cls[name] = t
	
	phdr = struct.unpack_from("!BBHI", buf)
	
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
	
	return api.send_msg(app, RawMsg(datapath, buf),
			reply_cls=reply_cls,
			reply_multi=reply_multi)


class RawMsg(MsgBase):
	def __init__(self, datapath, buf):
		# memo: it is strange that A) MsgBase requires datapath set 
		# on __init__, and B) datapath.send_msg takes that MsgBase 
		# like this: datapath.send_msg(RawMsg(datapath, buf))
		super(RawMsg, self).__init__(datapath)
		self.buf = buf

	def set_xid(self, xid):
		super(RawMsg, self).set_xid(xid)
		hdr = list(struct.unpack_from("!BBHI", self.buf))
		hdr[3] = xid
		self.buf = struct.pack("!BBHI", *hdr) + self.buf[8:]

	def serialize(self):
		pass

ryu.base.app_manager.require_app('ryu.app.ofctl.service', api_style=True)
