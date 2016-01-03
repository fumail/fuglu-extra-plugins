IMAP Copy
---------

This plugins stores a copy of the message to an IMAP mailbox if it matches certain criteria (SuspectFilter).
The rulefile works similar to the archive plugin. As third column you have to provide IMAP account data in the form:

```
<protocol>://<username>:<password>@<servernameorip>[:port]/<mailbox>
```

```<protocol>``` is either imap or imaps


Example `/etc/fuglu/imapcopy.regex`:

```
to_domain       example\.org     imaps://spam@example.org:secretpass@mymailserver.example.org/INBOX.archive
```

