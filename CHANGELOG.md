# Changes

## v1.8.1 [2022/12/14] 

Fixed a bug when rules with fields with `null` values would not be converted properly.

## v1.8.1 [2022/12/06] 

Stopped fixing regular expressions in `|re` fields during sigma rule conversion to work with the regex crate as we fixed the regular expressions upstream.

## v1.8.1 [2022/10/4] 

Automatically update sigma rules daily.

## v1.4.2 [2022/07/20]

Include Channel in rule filename.

## v1.2.2 [2022/05/21]

Deprecated Japanese localization support: `title_jp`, `details_jp`, `description_jp`