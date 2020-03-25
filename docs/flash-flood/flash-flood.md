# Flash Flood and the DSS

[flash-flood](https://github.com/HumanCellAtlas/flash-flood) is
an event recorder and streamer built on top of AWS S3, supporting distributed
writes and fast distributed bulk reads.

The flash-flood library was written to provide an [event journal](https://en.wikipedia.org/wiki/Journaling_file_system)
for data store transactions. Whenver a transaction occurrs in the data store,
it is added to the journal by flash-flood. Those events can then be retrieved
by downstream services (e.g., a data store search engine, or an index of data
in the data store) and processed.

For example, consider a hypothetical component: a search index that powers a search
engine to allow users to search across all data and metadata contained in the
data store. The search index should contain fresh information, so when data is
added, updated, or removed, those should be reflected in the search index. But
constant re-indexing of the documents in the search index should not be required.

Now suppose that to achieve this, the hypothetical search index updates its search
index once per day to achieve this.  Then the search engine can use flash-flood to 
access the data store event journals, starting from when the last indexing operation 
occurred, and ending at the current time. This stream of events could then be used to
construct a record of what data and documents were added, removed, or updated.

Note: We mention a hypothetical search index above. Elasticsearch provides search
functionality for the data store already, but Elasticsearch is baked into the
data store directly and does not utilize flash-flood. However, deprecating
Elasticsearch from the data store has been on the roadmap for [some time], and
once it has been removed from the data store it can be refactored as a downstream
component that consumes flash-flood events to update its index.

  [some time]: https://github.com/HumanCellAtlas/data-store/issues/906

Example flash-flood usage is given in [flash-flood.ipynb].

  [flash-flood.ipynb]: https://github.com/HumanCellAtlas/flash-flood/blob/master/intro.ipynb
