# Changes

## v2.4.0 [2023/04/28] 

Started to self host config files when converting rules from Sigma as the sigmac tool is deprecated and not updated anymore.

## v2.3.0 [2023/03/24] 

`deprecated` and `unsupported` sigma rules are now also being added to the hayabusa-rules repository.

## v2.2.2 [2023/02/22] 

Hayabusa now supports rules that use `base64offset|contains`.

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