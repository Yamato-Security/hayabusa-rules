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
| endswith              |          2908 |              271 |
| endswithfield         |             0 |                2 |
| endswithǀwindash      |             2 |                0 |
| equalsfield           |             0 |                1 |
| exists                |             0 |                0 |
| fieldref              |             1 |                0 |
| fieldrefǀendswith     |             0 |                0 |
| re                    |           167 |               11 |
| reǀi                  |             0 |                0 |
| reǀm                  |             0 |                0 |
| reǀs                  |             0 |                0 |
| startswith            |           441 |                6 |

# Hayabusa unsupported field modifiers
| Field Modifier                |   Sigma Count |   Hayabusa Count |
|:------------------------------|--------------:|-----------------:|
| containsǀexpand               |             1 |                0 |
| expand                        |             9 |                0 |
| gt                            |             0 |                0 |
| gte                           |             0 |                0 |
| lt                            |             0 |                0 |
| lte                           |             0 |                0 |
| utf16beǀbase64offsetǀcontains |             0 |                0 |
| utf16leǀbase64offsetǀcontains |             0 |                0 |
| utf16ǀbase64offsetǀcontains   |             0 |                0 |
| wideǀbase64offsetǀcontains    |             0 |                0 |

# Hayabusa supported correlation rules
| Correlation Rule            |   Sigma Count |   Hayabusa Count |
|:----------------------------|--------------:|-----------------:|
| event_count                 |             0 |                0 |
| event_count (with group-by) |             0 |                1 |
| value_count                 |             0 |                0 |
| value_count (with group-by) |             0 |                1 |

# Hayabusa un-supported correlations rules
| Correlation Rule               |   Sigma Count |   Hayabusa Count |
|:-------------------------------|--------------:|-----------------:|
| temporal_count                 |             0 |                0 |
| temporal_count (with group-by) |             0 |                0 |

This document is being dynamically updated based on the latest rules.  
Last Update: 2024/10/18  
Author: Fukusuke Takahashi