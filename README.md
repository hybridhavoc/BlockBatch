# BlockBatch
Script which assists a Mastodon administrator with batch operations against different forms of blocks. It takes a configuration file which includes:

- **access-token** : Mastodon access token with admin permissions.
- **server** : Mastodon server domain, i.e. mastodon.social.
- **log-directory** : Path to a directory for logs.
- **logging-level** : Specify the log level, either error, info, or debug.

Sample config file provided. These may also be provided as arguments whne calling the script. In addition to these, there are more arguments:

- **type** : Type of block to be acted on. Options include domain, email, and ip.
- **action** : The action to be taken. Options include lookup, add, update, remove.
- **file** : The comma-delimited csv file you want to use as a list.
- **mode** : Specify whether you want to run this in update mode or report mode. If run in report mode, no actions will be taken. If run in update mode, actions will be taken.

Sample CSVs for domains, emails, and IPs have been included. Each have required attributes. An example command might look like:

> py blockbatch.py -c config.json --type domain --action remove --file sample_domain.csv --mode update