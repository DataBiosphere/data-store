# Flash Flood and the DSS

[HumanCellAtlas/flash-flood](https://github.com/HumanCellAtlas/flash-flood) is
an event recorder and streamer built on top of AWS S3, supporting distributed
writes and fast distributed bulk reads.

The original intent was for it to be used to provide a journal of events of
Data Store transactions. Transactions, when they occurred, would be logged
with flash-flood, then those events could be retrieved by a downstream
service (e.g., Azul, Query Service) for processing. For consumers, the
thinking was that the current ElasticSearch functionality could be stripped
from the DSS, and refactored as a separate component ingesting event data
from Flash Flood to complie its own search index. Were events stored as JSON
data, those events could also be searched using JMESPath. (The key point here
is that flash-flood cannot implement search in the DSS per se, though it could
be used to supply some independent component with data to search through.)

This is not yet the case. Deprecating ElasticSearch from the DSS has been on
the roadmap for [some time] but the infrastructure to use flash-flood as a
kind of search backend has not been developed as of time of writing.

  [some time]: https://github.com/HumanCellAtlas/data-store/issues/906

Example flash-flood usage is given in [flash-flood.ipynb](flash-flood.ipynb).