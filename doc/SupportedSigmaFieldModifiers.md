# Hayabusa supported field modifiers
| Field Modifier        |   Sigma Count |   Hayabusa Count |
|:----------------------|--------------:|-----------------:|
| all                   |            13 |                0 |
| base64offsetǀcontains |             7 |                0 |
| cased                 |             0 |                0 |
| cidr                  |            34 |                0 |
| contains              |          2752 |               21 |
| containsǀall          |           975 |                0 |
| containsǀallǀwindash  |             4 |                0 |
| containsǀwindash      |            78 |                0 |
| endswith              |          2908 |              270 |
| endswithfield         |             0 |                2 |
| endswithǀwindash      |             2 |                0 |
| equalsfield           |             0 |                1 |
| exists                |             0 |                0 |
| re                    |           167 |               11 |
| reǀi                  |             0 |                0 |
| reǀm                  |             0 |                0 |
| reǀs                  |             0 |                0 |
| startswith            |           441 |                6 |

# Hayabusa unsupported field modifiers
| Field Modifier   |   Sigma Count |   Hayabusa Count |
|:-----------------|--------------:|-----------------:|
| base64ǀutf16be   |             0 |                0 |
| base64ǀutf16le   |             0 |                0 |
| base64ǀwide      |             0 |                0 |
| containsǀexpand  |             1 |                0 |
| expand           |             9 |                0 |
| fieldref         |             1 |                0 |
| gt               |             0 |                0 |
| gte              |             0 |                0 |
| lt               |             0 |                0 |
| lte              |             0 |                0 |

Updated: 2024/10/08  
Author: Fukusuke Takahashi