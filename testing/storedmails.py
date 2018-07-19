# -*- coding: utf-8 -*-

mail_html = b""" Received: from AAAAA.AAAAA.AAAAAAAAA.AA (AAAAA.AAAAA.AAAAAAAAA.AA [DD.DDD.DDD.DDD])
	by AAAAA.AAAAAAAAA.AA (Postfix) with ESMTPS id 3E913321CE6
	for <AAAAAA.AAAAAA@AAAAAAAAAAAA.AA>; Tue, 17 Jul 2018 14:21:31 +0200 (CEST)
Date: Tue, 17 Jul 2018 20:21:15 +0800
From: AD - team <AAAAAAAA.AAAAAAA@AAAAAAAAAAA.AA>
To: ulrich.koller@lerchpartner.ch
Message-ID: <10490727656033017658.4ADEC29DAEF43614@AAAAAAAAAAAA.AA>
Subject: Your AD billing
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_59790_1894464111.1706236854191164988"

------=_Part_59790_1894464111.1706236854191164988
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: quoted-printable

<html>
<body>
<span style=3D"text-transform:uppercase">Thanks for being with AD</span>
<br><br><br>
Hi,=20
<br><br>
=20
<br>
=0DPayment due date: 17 Jul, 2018.<br>=0DPayment reference: DDDDDDDDDDDD<br=
>=0D<b>Amount: &pound;DDD.DD</b>.<br>=0D
<br>
<a href=3Dhttp://toBeDetected.com.br/Jul2018/En/Statement/Invoice-DDDDDDDDD-DDDDD=
D/>See Bill Here.</a> <span style=3D"text-transform:uppercase">(AAAAAA.AAAA=
AA@AAAAAAAAAAAA.AA)</span>
<br>
AD billing statement message.
<br><br><br>
Best Wishes,<br>
The AD - payment<br>
</body>
</html>
------=_Part_59790_1894464111.1706236854191164988-- """

# dummy mail containing only link: "www.co.uk"
mail_base64 = b"""Content-Type: text/plain; charset="utf-8"
MIME-Version: 1.0
Content-Transfer-Encoding: base64
To: Recipient <rec@aaaaaaa.aa>
From: Author <auth@aaaaaa.aa>
Subject: Simple test message

d3d3LmNvLnVr
"""
