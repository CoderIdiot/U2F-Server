#!/usr/bin/env python
# coding=utf-8

from M2Crypto import EC
from hashlib import sha256

prefix = "3059301306072a8648ce3d020106082a8648ce3d030107034200".decode('hex')
tail_key = '04EC4FDC9FBDECFE8F21B178693703733C0E3A96BE41590CCF98DCFB2DA8A19BA8A3854E8B5E57D1E01AEDCA8F28B0B643BC890174A08018C34F91D0A79D064548'.decode('hex')

ec = EC.pub_key_from_der(prefix + tail_key)

msg = '002122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F400102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F200000000004EC4FDC9FBDECFE8F21B178693703733C0E3A96BE41590CCF98DCFB2DA8A19BA8A3854E8B5E57D1E01AEDCA8F28B0B643BC890174A08018C34F91D0A79D064548'.decode('hex')
sig = '304402206613ECA917F891ABADEAB63054CE7DFE3F32268FCE7D0AF4B37C6000C9D13B2B022067E717B413597268EF28EC72EE79135EB87026DB14E64776C15CD7335D95402A'.decode('hex')

h = sha256()
h.update(msg)
result = ec.verify_dsa_asn1(h.digest(), sig)
print result