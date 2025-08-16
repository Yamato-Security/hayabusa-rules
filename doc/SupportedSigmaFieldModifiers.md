# Hayabusa supported field modifiers
| Field Modifier             |   Sigma Count |   Hayabusa Count |
|:---------------------------|--------------:|-----------------:|
| all                        |            13 |                0 |
| base64offsetǀcontains      |             7 |                0 |
| base64ǀcontains            |             1 |                0 |
| cidr                       |            34 |                0 |
| contains                   |          2858 |               21 |
| containsǀall               |          1010 |                0 |
| containsǀallǀwindash       |             4 |                0 |
| containsǀexpand            |             1 |                0 |
| containsǀwindash           |            80 |                0 |
| endswith                   |          3010 |              273 |
| endswithǀwindash           |             2 |                0 |
| expand                     |             9 |                0 |
| fieldref                   |             1 |                1 |
| fieldrefǀendswith          |             0 |                2 |
| re                         |           169 |               11 |
| startswith                 |           465 |                6 |
| wideǀbase64offsetǀcontains |             2 |                0 |

# Hayabusa unsupported field modifiers
Currently, everything is supported.


# Hayabusa supported correlation rules
| Correlation Rule            |   Sigma Count |   Hayabusa Count |
|:----------------------------|--------------:|-----------------:|
| event_count (with group-by) |             0 |                1 |
| value_count (with group-by) |             0 |                2 |

# Hayabusa unsupported correlations rules
Currently, everything is supported.


This document is being dynamically updated based on the latest rules.  
Last Update: 2025/08/17  
Author: Fukusuke Takahashi