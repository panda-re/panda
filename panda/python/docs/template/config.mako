<%!
    # Template configuration. Copy over in your template directory
    # (used with `--template-dir`) and adapt as necessary.
    # Note, defaults are loaded from this distribution file, so your
    # config.mako only needs to contain values you want overridden.
    # You can also run pdoc with `--config KEY=VALUE` to override
    # individual values.

    # If set, insert Google Custom Search search bar widget above the sidebar index.
    # The whitespace-separated tokens represent arbitrary extra queries (at least one
    # must match) passed to regular Google search. Example:
    #google_search_query = 'inurl:github.com/panda-re/panda/blob/master/panda/python site:docs.panda.re/'

    # Enable offline search using Lunr.js. For explanation of 'fuzziness' parameter, which is
    # added to every query word, see: https://lunrjs.com/guides/searching.html#fuzzy-matches
    # If 'index_docstrings' is False, a shorter index is built, indexing only
    # the full object reference names.
    lunr_search = {'fuzziness': 1, 'index_docstrings': True}

%>
