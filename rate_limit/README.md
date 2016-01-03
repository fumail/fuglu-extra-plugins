
```
This is a generic rolling window rate limiting plugin. It allows limiting the amount of accepted messages based on any combination of supported SuspectFilter fields.
    This means you could for example limit the number of similar subjects by sender domain to implement a simple bulk filter.

Important notes:
    - This plugin is experimental and has not been tested in production
    - This plugin only makes sense in pre-queue mode.
    - The content filter stage is usually *not* the best place to implement rate-limiting.
      Faster options are postfix built-in rate limits or a policy access daemon
      which doesn't need to accept the full message to make a decision
    - the backends don't automatically perform global expiration of all events.
      Old entries are only cleared per event the next time the same event happens.
      Add a cron job for your backend to clear all old events from time to time.

Supported backends:
    - memory: stores events in memory. Do not use this in production.
    - sqlalchemy: Stores events in a SQL database. Recommended for small/low-traffic setups
    - redis: stores events in a redis database. This is the fastest and therefore recommended backend.

Configuration example for redis. Prerequisite: python redis module
    backendtype = redis
    backendconfig = localhost:6379:0

Configuration example for mysql: Prerequisite: python sqlalchemy module. The database must exist. The table will be created automatically.
    backendtype = sqlalchemy
    backendconfig = mysql://root@localhost/fuglu

ratelimit.conf format: (not final yet)

Each limiter is defined by a line which must match the following format. Each limiter is evaluated in the order specified.
```
limit name=**name** rate=**max**/**timeframe** fields=**fieldlist** [match=/**filter regex**/ [skip=**skiplist** ]] action=**action** message=**message**

 * **name**        : a descriptive name for this filter, one word. Required to reference in skip lists
 * **max**         : the maximum number of events that may occur in the specified timeframe before an action is limited.
                  Specify a negative value to indicate "no limit"
 * **timeframe**   : Timeframe for the limit
 * **fields**      : comma separated list of fields which should be used as unique values to limit
 * **match** (optional): regular expression to apply to the actuall values. The limiter is only applied if this regular expression matches.
                      If the limiter consists of multiple input fields,
                      The regex will be applied to the comma separated list of field values.
 * **skip** (optional):  Comma separated list of subsequent limiter names, that should be skipped if this this limiter's regex matched the input values.
                      Used for overrides.
 * **action**      : Action that should be performed if the limit is exceeded. ( REJECT / DEFER / ... )
 * **message**     : Message returned to the connecting client


Examples:

```
# no sending limit for our newsletter
limit name=newsletter rate=-1/1 fields=from_address match=/^newsletter@example\.com$/ skip=fromaddr,serverhelo action=DUNNO message=OK

# max 10 messages in 30 seconds per unique sender address:
limit name=fromaddr rate=10/30 fields=from_address action=REJECT message=Too many messages from ${from_address}

# max 100 messages with same subject per hour per server helo
limit name=serverhelo rate=100/3600 fields=clienthelo,subject action=REJECT message=Bulk message detected
```