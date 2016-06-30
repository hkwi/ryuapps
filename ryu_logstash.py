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
		
		tcls = {1:V1, 3:V3}.get(datapath.ofproto.OFP_VERSION, Base)
		tcls(self, s, datapath).collect()

class Base(object):
	def __init__(self, app, logstash, datapath):
		self.app = app
		self.logstash = logstash
		self.datapath = datapath
	
	def collect(self):
		self.aggregate_stats()
		self.flow_stats()
		self.table_stats()
		self.port_stats()
		self.queue_stats()
		self.group_stats()
		self.meter_stats()
	
	def send(self, unit, req, tm):
		with OxmJsonPatch(self.datapath.ofproto):
			obj = to_jsondict(unit)
			obj["datapath_hex"] = "0x%x" % self.datapath.id
			obj["ofp_version"] = self.datapath.ofproto.OFP_VERSION
			obj["request"] = to_jsondict(req)
			obj["rtt"] = time.time()-tm
			self.logstash.send(msgpack.dumps(obj))

	def aggregate_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPAggregateStatsRequest(datapath, 0,
			datapath.ofproto.OFPTT_ALL,
			datapath.ofproto.OFPP_ANY,
			datapath.ofproto.OFPG_ANY, 0, 0,
			datapath.ofproto_parser.OFPMatch())
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPAggregateStatsReply, reply_multi=True):
			self.send(msg.body, req, tm)

	def flow_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPFlowStatsRequest(datapath)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPFlowStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)

	def table_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPTableStatsRequest(datapath, 0)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPTableStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)

	def port_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPPortStatsRequest(datapath, flags=0, port_no=datapath.ofproto.OFPP_ANY)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPPortStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)

	def queue_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPQueueStatsRequest(datapath)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPQueueStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)

	def group_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPGroupStatsRequest(datapath)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPGroupStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)

	def meter_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPMeterStatsRequest(datapath)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPMeterStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)


class V1(Base):
	def collect(self):
		self.aggregate_stats()
		self.flow_stats()
		self.table_stats()
		self.port_stats()
		self.queue_stats()

	def aggregate_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPAggregateStatsRequest(datapath, 0,
			datapath.ofproto_parser.OFPMatch(),
			0xff,
			datapath.ofproto.OFPP_NONE)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPAggregateStatsReply, reply_multi=True):
			for body in msg.body:
				self.send(body, req, tm)

	def flow_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPFlowStatsRequest(datapath, 0,
				datapath.ofproto_parser.OFPMatch(),
				0xff,
				datapath.ofproto.OFPP_NONE)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPFlowStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)

	def port_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_NONE)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPPortStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)

	def queue_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPQueueStatsRequest(datapath, 0,
			datapath.ofproto.OFPP_ALL,
			datapath.ofproto.OFPQ_ALL)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPQueueStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)


class V3(Base):
	def collect(self):
		self.aggregate_stats()
		self.flow_stats()
		self.table_stats()
		self.port_stats()
		self.queue_stats()
		self.group_stats()
	
	def aggregate_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPAggregateStatsRequest(datapath)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPStatsReply, reply_multi=True):
			self.send(msg.body, req, tm)

	def flow_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPFlowStatsRequest(datapath)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)

	def table_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPTableStatsRequest(datapath, 0)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)

	def port_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPPortStatsRequest(datapath)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)

	def queue_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPQueueStatsRequest(datapath)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)

	def group_stats(self):
		datapath = self.datapath
		p = datapath.ofproto_parser
		tm = time.time()
		req = p.OFPGroupStatsRequest(datapath)
		for msg in api.send_msg(self.app, req, reply_cls=p.OFPStatsReply, reply_multi=True):
			for b in msg.body:
				self.send(b, req, tm)


class OxmJsonPatch(object):
	@staticmethod
	def _to_jsondict(k, uv):
		if isinstance(uv, tuple):
			payload = dict(value=uv[0], mask=uv[1])
		else:
			payload = dict(value=uv)
		return {k:payload, "__type":"OXMTlv"}
	
	@staticmethod
	def _from_jsondict(j):
		ks = [k for k in j.keys() if not k.startswith("__")]
		assert len(ks) == 1
		field = ks[0]
		value = j[field]["value"]
		mask = j[field].get("mask")
		if mask is None:
			return (field, value)
		else:
			return (field, (value, mask))
	
	def __init__(self, module):
		self.module = module
		self.save = (
			module.oxm_from_jsondict,
			module.oxm_to_jsondict,
		)
	
	def __enter__(self):
		self.module.oxm_from_jsondict = OxmJsonPatch._from_jsondict
		self.module.oxm_to_jsondict = OxmJsonPatch._to_jsondict

	def __exit__(self, exc_type, exc_value, traceback):
		self.module.oxm_from_jsondict = self.save[0]
		self.module.oxm_to_jsondict = self.save[1]
