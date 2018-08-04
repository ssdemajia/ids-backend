# coding: utf-8
from sqlalchemy import Column, DateTime, Index, Integer, SmallInteger, String, Text
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class AcidAg(db.Model):
    __tablename__ = 'acid_ag'

    ag_id = db.Column(db.Integer, primary_key=True, index=True)
    ag_name = db.Column(db.String(40))
    ag_desc = db.Column(db.Text)
    ag_ctime = db.Column(db.DateTime)
    ag_ltime = db.Column(db.DateTime)


class AcidAgAlert(db.Model):
    __tablename__ = 'acid_ag_alert'
    __table_args__ = (
        db.Index('ag_sid', 'ag_sid', 'ag_cid'),
    )

    ag_id = db.Column(db.Integer, primary_key=True, nullable=False, index=True)
    ag_sid = db.Column(db.Integer, primary_key=True, nullable=False)
    ag_cid = db.Column(db.Integer, primary_key=True, nullable=False)


class AcidEvent(db.Model):
    __tablename__ = 'acid_event'

    sid = db.Column(db.Integer, primary_key=True, nullable=False)
    cid = db.Column(db.Integer, primary_key=True, nullable=False)
    signature = db.Column(db.Integer, nullable=False, index=True)
    sig_name = db.Column(db.String(255), index=True)
    sig_class_id = db.Column(db.Integer, index=True)
    sig_priority = db.Column(db.Integer, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    ip_src = db.Column(db.Integer, index=True)
    ip_dst = db.Column(db.Integer, index=True)
    ip_proto = db.Column(db.Integer, index=True)
    layer4_sport = db.Column(db.Integer, index=True)
    layer4_dport = db.Column(db.Integer, index=True)


class AcidIpCache(db.Model):
    __tablename__ = 'acid_ip_cache'

    ipc_ip = db.Column(db.Integer, primary_key=True, index=True)
    ipc_fqdn = db.Column(db.String(50))
    ipc_dns_timestamp = db.Column(db.DateTime)
    ipc_whois = db.Column(db.Text)
    ipc_whois_timestamp = db.Column(db.DateTime)


class BaseRole(db.Model):
    __tablename__ = 'base_roles'

    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(20), nullable=False)
    role_desc = db.Column(db.String(75), nullable=False)


class BaseUser(db.Model):
    __tablename__ = 'base_users'

    usr_id = db.Column(db.Integer, primary_key=True)
    usr_login = db.Column(db.String(25), nullable=False, index=True)
    usr_pwd = db.Column(db.String(32), nullable=False)
    usr_name = db.Column(db.String(75), nullable=False)
    role_id = db.Column(db.Integer, nullable=False)
    usr_enabled = db.Column(db.Integer, nullable=False)


class Datum(db.Model):
    __tablename__ = 'data'

    sid = db.Column(db.Integer, primary_key=True, nullable=False)
    cid = db.Column(db.Integer, primary_key=True, nullable=False)
    data_payload = db.Column(db.Text)


class Detail(db.Model):
    __tablename__ = 'detail'

    detail_type = db.Column(db.Integer, primary_key=True)
    detail_text = db.Column(db.Text, nullable=False)


class Encoding(db.Model):
    __tablename__ = 'encoding'

    encoding_type = db.Column(db.Integer, primary_key=True)
    encoding_text = db.Column(db.Text, nullable=False)


class Event(db.Model):
    __tablename__ = 'event'

    sid = db.Column(db.Integer, primary_key=True, nullable=False)
    cid = db.Column(db.Integer, primary_key=True, nullable=False)
    signature = db.Column(db.Integer, nullable=False, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)


class Icmphdr(db.Model):
    __tablename__ = 'icmphdr'

    sid = db.Column(db.Integer, primary_key=True, nullable=False)
    cid = db.Column(db.Integer, primary_key=True, nullable=False)
    icmp_type = db.Column(db.Integer, nullable=False, index=True)
    icmp_code = db.Column(db.Integer, nullable=False)
    icmp_csum = db.Column(db.SmallInteger)
    icmp_id = db.Column(db.SmallInteger)
    icmp_seq = db.Column(db.SmallInteger)


class IdsEvent(db.Model):
    __tablename__ = 'ids_event'

    sid = db.Column(db.Integer, primary_key=True, nullable=False)
    cid = db.Column(db.Integer, primary_key=True, nullable=False)
    signature = db.Column(db.Integer, nullable=False, index=True)
    sig_name = db.Column(db.String(255), index=True)
    sig_class_id = db.Column(db.Integer, index=True)
    sig_priority = db.Column(db.Integer, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    ip_src = db.Column(db.Integer, index=True)
    ip_dst = db.Column(db.Integer, index=True)
    ip_proto = db.Column(db.Integer, index=True)
    layer4_sport = db.Column(db.Integer, index=True)
    layer4_dport = db.Column(db.Integer, index=True)


class Iphdr(db.Model):
    __tablename__ = 'iphdr'

    sid = db.Column(db.Integer, primary_key=True, nullable=False)
    cid = db.Column(db.Integer, primary_key=True, nullable=False)
    ip_src = db.Column(db.Integer, nullable=False, index=True)
    ip_dst = db.Column(db.Integer, nullable=False, index=True)
    ip_ver = db.Column(db.Integer)
    ip_hlen = db.Column(db.Integer)
    ip_tos = db.Column(db.Integer)
    ip_len = db.Column(db.SmallInteger)
    ip_id = db.Column(db.SmallInteger)
    ip_flags = db.Column(db.Integer)
    ip_off = db.Column(db.SmallInteger)
    ip_ttl = db.Column(db.Integer)
    ip_proto = db.Column(db.Integer, nullable=False)
    ip_csum = db.Column(db.SmallInteger)


class Opt(db.Model):
    __tablename__ = 'opt'

    sid = db.Column(db.Integer, primary_key=True, nullable=False)
    cid = db.Column(db.Integer, primary_key=True, nullable=False)
    optid = db.Column(db.Integer, primary_key=True, nullable=False)
    opt_proto = db.Column(db.Integer, nullable=False)
    opt_code = db.Column(db.Integer, nullable=False)
    opt_len = db.Column(db.SmallInteger)
    opt_data = db.Column(db.Text)


class Reference(db.Model):
    __tablename__ = 'reference'

    ref_id = db.Column(db.Integer, primary_key=True)
    ref_system_id = db.Column(db.Integer, nullable=False)
    ref_tag = db.Column(db.Text, nullable=False)


class ReferenceSystem(db.Model):
    __tablename__ = 'reference_system'

    ref_system_id = db.Column(db.Integer, primary_key=True)
    ref_system_name = db.Column(db.String(20))


class Schema(db.Model):
    __tablename__ = 'schema'

    vseq = db.Column(db.Integer, primary_key=True)
    ctime = db.Column(db.DateTime, nullable=False)


class Sensor(db.Model):
    __tablename__ = 'sensor'

    sid = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.Text)
    interface = db.Column(db.Text)
    filter = db.Column(db.Text)
    detail = db.Column(db.Integer)
    encoding = db.Column(db.Integer)
    last_cid = db.Column(db.Integer, nullable=False)


class SigClas(db.Model):
    __tablename__ = 'sig_class'

    sig_class_id = db.Column(db.Integer, primary_key=True, index=True)
    sig_class_name = db.Column(db.String(60), nullable=False, index=True)


class SigReference(db.Model):
    __tablename__ = 'sig_reference'

    sig_id = db.Column(db.Integer, primary_key=True, nullable=False)
    ref_seq = db.Column(db.Integer, primary_key=True, nullable=False)
    ref_id = db.Column(db.Integer, nullable=False)


class Signature(db.Model):
    __tablename__ = 'signature'

    sig_id = db.Column(db.Integer, primary_key=True)
    sig_name = db.Column(db.String(255), nullable=False, index=True)
    sig_class_id = db.Column(db.Integer, nullable=False, index=True)
    sig_priority = db.Column(db.Integer)
    sig_rev = db.Column(db.Integer)
    sig_sid = db.Column(db.Integer)
    sig_gid = db.Column(db.Integer)


class Tcphdr(db.Model):
    __tablename__ = 'tcphdr'

    sid = db.Column(db.Integer, primary_key=True, nullable=False)
    cid = db.Column(db.Integer, primary_key=True, nullable=False)
    tcp_sport = db.Column(db.SmallInteger, nullable=False, index=True)
    tcp_dport = db.Column(db.SmallInteger, nullable=False, index=True)
    tcp_seq = db.Column(db.Integer)
    tcp_ack = db.Column(db.Integer)
    tcp_off = db.Column(db.Integer)
    tcp_res = db.Column(db.Integer)
    tcp_flags = db.Column(db.Integer, nullable=False, index=True)
    tcp_win = db.Column(db.SmallInteger)
    tcp_csum = db.Column(db.SmallInteger)
    tcp_urp = db.Column(db.SmallInteger)


class Udphdr(db.Model):
    __tablename__ = 'udphdr'

    sid = db.Column(db.Integer, primary_key=True, nullable=False)
    cid = db.Column(db.Integer, primary_key=True, nullable=False)
    udp_sport = db.Column(db.SmallInteger, nullable=False, index=True)
    udp_dport = db.Column(db.SmallInteger, nullable=False, index=True)
    udp_len = db.Column(db.SmallInteger)
    udp_csum = db.Column(db.SmallInteger)
