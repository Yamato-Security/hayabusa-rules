# Hayabusa supported field modifiers
| Field Modifier                |   Sigma Count |   Hayabusa Count |
|:------------------------------|--------------:|-----------------:|
| all                           |            13 |                0 |
| base64offsetǀcontains         |             7 |                0 |
| cased                         |             0 |                0 |
| cidr                          |            34 |                0 |
| contains                      |          2769 |               21 |
| containsǀall                  |           978 |                0 |
| containsǀallǀwindash          |             4 |                0 |
| containsǀcased                |             0 |                0 |
| containsǀwindash              |            78 |                0 |
| endswith                      |          2921 |              271 |
| endswithfield                 |             0 |                0 |
| endswithǀcased                |             0 |                0 |
| endswithǀwindash              |             2 |                0 |
| equalsfield                   |             0 |                0 |
| exists                        |             0 |                0 |
| fieldref                      |             1 |                1 |
| fieldrefǀcontains             |             0 |                0 |
| fieldrefǀendswith             |             0 |                2 |
| fieldrefǀstartswith           |             0 |                0 |
| gt                            |             0 |                0 |
| gte                           |             0 |                0 |
| lt                            |             0 |                0 |
| lte                           |             0 |                0 |
| re                            |           167 |               11 |
| reǀi                          |             0 |                0 |
| reǀm                          |             0 |                0 |
| reǀs                          |             0 |                0 |
| startswith                    |           445 |                6 |
| startswithǀcased              |             0 |                0 |
| utf16beǀbase64offsetǀcontains |             0 |                0 |
| utf16leǀbase64offsetǀcontains |             0 |                0 |
| utf16ǀbase64offsetǀcontains   |             0 |                0 |
| wideǀbase64offsetǀcontains    |             0 |                0 |

# Hayabusa unsupported field modifiers
| Field Modifier   |   Sigma Count |   Hayabusa Count |
|:-----------------|--------------:|-----------------:|
| containsǀexpand  |             1 |                0 |
| expand           |             9 |                0 |

# Hayabusa supported correlation rules
| Correlation Rule            |   Sigma Count |   Hayabusa Count |
|:----------------------------|--------------:|-----------------:|
| event_count                 |             0 |                0 |
| event_count (with group-by) |             0 |                1 |
| value_count                 |             0 |                0 |
| value_count (with group-by) |             0 |                2 |

# Hayabusa un-supported correlations rules
| Correlation Rule               |   Sigma Count |   Hayabusa Count |
|:-------------------------------|--------------:|-----------------:|
| temporal_count                 |             0 |                0 |
| temporal_count (with group-by) |             0 |                0 |

This document is being dynamically updated based on the latest rules.  
Last Update: 2024/12/14  
Author: Fukusuke Takahashi