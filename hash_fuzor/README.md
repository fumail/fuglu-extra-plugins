# The fuzor hash

Fuzor is a message digests similar to [pyzor](http://www.pyzor.org/)  by removing often changing parts from spam messages
(like links, email adresses etc). The resulting hash should uniquely identify the "structure"" of a spam message instead of the
 actual contents. In contrast to pyzor, fuzor will not make any assumptions about messages with no unique message body data.
This makes it less effective against very short message but will create less hash collisions which often cause pyzor to hit on
legitimate messages.

Note that in order to run fuzor, you'll need your own redis server to learn hashes from your spam traps etc. We do not provide
 a public fuzor server.

The fuglu fuzor plugin simply writes a spamassassin pseudo header to tell it how many spam messages with the same fuzor hash
have been encountered so far.

Spamassassin example configuration

```
header          FUZOR_SEEN         exists:X-FuZor-ID
describe        FUZOR_SEEN         Info: Msg seen by Fuzor
score           FUZOR_SEEN         0.001

header          FUZOR_LVL_1_2        X-FuZor-Lvl =~ /^[1-2]$/
describe        FUZOR_LVL_1_2        Fuzor suspect trap/feed traffic
score           FUZOR_LVL_1_2        1.5

header          FUZOR_LVL_3_9        X-FuZor-Lvl =~ /^[3-9]$/
describe        FUZOR_LVL_3_9        Fuzor low trap/feed traffic
score           FUZOR_LVL_3_9        2.0

header          FUZOR_LVL_D2         X-FuZor-Lvl =~ /^\d{2}$/
describe        FUZOR_LVL_D2         Fuzor medium trap/feed traffic
score           FUZOR_LVL_D2         3.0
tflags          FUZOR_LVL_D2         autolearn_force

header          FUZOR_LVL_D3         X-FuZor-Lvl =~ /^\d{3}$/
describe        FUZOR_LVL_D3         Fuzor high trap/feed traffic
score           FUZOR_LVL_D3         3.5
tflags          FUZOR_LVL_D3         autolearn_force


header          FUZOR_LVL_D4_8       X-FuZor-Lvl =~ /^\d{4,8}$/
describe        FUZOR_LVL_D4_8       Fuzor very high trap/feed traffic
score           FUZOR_LVL_D4_8       4.0
tflags          FUZOR_LVL_D4_8       autolearn_force

```
## Getting hash info

Sometimes it can be helpful to show how fuzor generates its digest. 
This can be done using the 'plugdummy.py' script included in fuglu.

```
plugdummy.py -p <path to the folder where fuzor.py resides> -e <test file>.eml fuzor.FuzorPrint
```

Example:
```
plugdummy.py -p /usr/local/fuglu/plugins/ -e spam1.eml fuzor.FuzorPrint
INFO:root:Input file created as /tmp/fuglu_dummy_message_in.eml
INFO:root:*** Running plugin: FuzorPrint ***
INFO:fuglu.plugin.FuzorPrint:Predigest: Itssharepriceisgoingthroughthe[LONG]Thecatmightbeoutofthebagnowbutthereisstillamassive[LONG]tobenefit.Isaythatthesecretisoutbecausethestockpricehasgoneuptwodaysinarowbuttherealityisthatitmustbeveryfewpeoplewhoknow[LONG]otherwiseitwould'vegonetentimeshigher.Incaseyoumissedmymessage[LONG]hereiswhatis[LONG]Abigpharmacorpisacquiringaminusculepubliccoandthisishappeningatapricethatis20timesgreaterthanwhereitcurrentlyis.Thismeansthatifyoucanput10thousandinrightnow,youwilltakeout200grandbyThursdaymorning.Thisinfoissolid.Itcomesfromanattorneywho'salongtimefriendofmineandwholiterallysawthe[LONG]documentswithhisowneyes.Youmustbewonderingwhatthecompany'stradingsymbolis,andIwillnotteaseyouanylongerit'sQlikeinQuality,SlikeinStraight,MlikeMaryandGlikeGoldThesefourletterstogethermakeupthecompany'stickerandthat'swhatyouwillneedtogivetoyourbroker,ortypeintoyouronlineaccounttopurchasethestock.Ihighlyrecommendyoudothisasquicklyaspossiblebecausethereisnoguaranteethatthepricewillremainthislowmuchlonger.Iexpectit'llcontinuetoriseandriseastheinsider[LONG]spreads.[LONG]thepotentialtobenefitis[LONG]gigantichere.-----BestRegards,KathleenAbbott
INFO:fuglu.plugin.FuzorPrint:343822ec606c4f03a716c72fc4972601: hash 48e89b1278ab0bae81f07ee1cddbfc42913a02a2
INFO:root:Result: DUNNO
```
Predigest shows the message content after fuzor removed all whitespaces, long words, urls, ...
The actual digest is the sha sum of the predigest.

