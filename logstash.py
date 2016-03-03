import socket
import time
import msgpack
import ryu.base.app_manager
from ryu.app.ofctl import api
from ryu.controller import dpset
from ryu.lib import hub

# These "logstash" section options can be defined in configuration file.
options = [
	ryu.cfg.IntOpt("interval", default=60, help="logstash collection interval"),
	ryu.cfg.StrOpt("host", default="127.0.0.1", help="logstash server addr"),
	ryu.cfg.IntOpt("port", default=25827, help="logstash server port"),
]

def to_jsondict(obj):
	for name, v in obj.to_jsondict().items():
		v["ryu"] = name
		return v

class Logstash(ryu.base.app_manager.RyuApp):
	'''
	Sends openflow stats information to logstash.
	
	logstash configuration looks like:
	
	input {
	  udp {
	    port => 25827
	    buffer_size => 1452
	    codec => msgpack { }
	  }
	}
	
	See also https://www.elastic.co/guide/en/logstash/current/plugins-codecs-collectd.html
	'''
	_CONTEXTS = {'dpset': dpset.DPSet}
	
	def __init__(self, *args, **kwargs):
		super(Logstash, self).__init__(*args, **kwargs)
		self.dpset = kwargs["dpset"]
		self.CONF.register_opts(options, group="logstash")
		hub.spawn(self.loop)
	
	def loop(self):
		while True:
			hub.sleep(self.CONF.logstash.interval)
			for _, datapath in self.dpset.get_all():
				hub.spawn(self.task, datapath)
	
	def task(self, datapath):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect((self.CONF.logstash.host, self.CONF.logstash.port))
		
		def send(unit, req, tm):
			obj = to_jsondict(unit)
			obj["datapath_id"] = datapath.id
			obj["datapath_hex"] = hex(datapath.id)
			obj["request"] = to_jsondict(req)
			obj["rtt"] = time.time()-tm
			s.send(msgpack.dumps(obj))
		
		tm = time.time()
		p = datapath.ofproto_parser
		req = p.OFPAggregateStatsRequest(datapath, 0,
			datapath.ofproto.OFPTT_ALL,
			datapath.ofproto.OFPP_ANY,
			datapath.ofproto.OFPG_ANY, 0, 0,
			datapath.ofproto_parser.OFPMatch())
		for msg in api.send_msg(self, req, reply_cls=p.OFPAggregateStatsReply, reply_multi=True):
			send(msg.body, req, tm)
		
		tm = time.time()
		req = p.OFPFlowStatsRequest(datapath)
		for msg in api.send_msg(self, req, reply_cls=p.OFPFlowStatsReply, reply_multi=True):
			for b in msg.body:
				send(b, req, tm)
		
		tm = time.time()
		req = p.OFPTableStatsRequest(datapath, 0)
		for msg in api.send_msg(self, req, reply_cls=p.OFPTableStatsReply, reply_multi=True):
			for b in msg.body:
				send(b, req, tm)
		
		tm = time.time()
		req = p.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
		for msg in api.send_msg(self, req, reply_cls=p.OFPPortStatsReply, reply_multi=True):
			for b in msg.body:
				send(b, req, tm)
		
		tm = time.time()
		req = p.OFPQueueStatsRequest(datapath, 0,
			datapath.ofproto.OFPP_ANY,
			datapath.ofproto.OFPQ_ALL)
		for msg in api.send_msg(self, req, reply_cls=p.OFPQueueStatsReply, reply_multi=True):
			for b in msg.body:
				send(b, req, tm)
		
		tm = time.time()
		req = p.OFPGroupStatsRequest(datapath, 0, datapath.ofproto.OFPG_ALL)
		for msg in api.send_msg(self, req, reply_cls=p.OFPGroupStatsReply, reply_multi=True):
			for b in msg.body:
				send(b, req, tm)
		
		tm = time.time()
		req = p.OFPMeterStatsRequest(datapath, 0, datapath.ofproto.OFPM_ALL)
		for msg in api.send_msg(self, req, reply_cls=p.OFPMeterStatsReply, reply_multi=True):
			for b in msg.body:
				send(b, req, tm)
