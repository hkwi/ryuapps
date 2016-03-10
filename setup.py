try:
	from setuptools import setup
except:
	from distutils.core import setup

setup(name="ryuapps",
	version="0.1",
	description="Openflow ryu utility apps",
	author="Hiroaki KAWAI",
	author_email="hiroaki.kawai@gmail.com",
	url="https://github.com/hkwi/ryuapps",
	py_modules=["ryu_logstash", "ryu_rproxy"])
