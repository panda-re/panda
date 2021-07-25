<!doctype html>
<html lang="${html_lang}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1">
    <title>Search</title>
    <link rel="preload stylesheet" as="style" href="https://cdnjs.cloudflare.com/ajax/libs/10up-sanitize.css/11.0.1/sanitize.min.css" integrity="sha256-PK9q560IAAa6WVRRh76LtCaI8pjTJ2z11v0miyNNjrs=" crossorigin>
    <link rel="preload stylesheet" as="style" href="https://cdnjs.cloudflare.com/ajax/libs/10up-sanitize.css/11.0.1/typography.min.css" integrity="sha256-7l/o7C8jubJiy74VsKTidCy1yBkRtiUGbVkYBylBqUg=" crossorigin>
    <style>
        body {margin: 0 1em;}
        footer,
        #search-status {
            font: 14px normal;
            color: grey;
        }

        footer {text-align: right;}

        a {
            color: #058;
            text-decoration: none;
            transition: color .3s ease-in-out;
        }
        a:hover {color: #e82;}

        li {padding-top: 10px;}
    </style>
    <base target="_parent">
</head>
<body>
<noscript>
    JavaScript is not supported/enabled in your browser. The search feature won't work.
</noscript>
<main>
    <h3 id="search-status"></h3>
    <ul id="search-results"></ul>
</main>
<footer>
    <p>Search results provided by <a href="https://lunrjs.com">Lunr.js</a></p>
</footer>

<script src="index.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/lunr.js/2.3.8/lunr.min.js" integrity="sha512-HiJdkRySzXhiUcX2VweXaiy8yeY212ep/j51zR/z5IPCX4ZUOxaf6naJ/0dQL/2l+ZL+B9in/u4nT8QJZ/3mig==" crossorigin></script>
<script>
    'use strict';

    const lunr_index = build_index();
    search(decodeURIComponent(new URL(window.location).hash.substring(1)));

    function set_status(message) {
        document.getElementById('search-status').textContent = message;
    }

    async function build_index() {
        return lunr(function () {
            this.ref('i');
            this.field('name', {boost: 10});
            this.field('ref', {boost: 5});
            this.field('doc');
            this.metadataWhitelist = ['position'];

            INDEX.forEach((doc, i) => {
                const parts = doc.ref.split('.');
                doc['name'] = parts[parts.length - 1];
                doc['i'] = i;

                this.add(doc);
            }, this);
        });
    }

    function search(query) {
        _search(query).catch(err => {
            set_status("Something went wrong. See development console for details.");
            throw err;
        });
    }

    async function _search(query) {
        if (!query) {
            set_status('No query provided, so there is nothing to search.');
            return;
        }

        const fuzziness = ${int(lunr_search.get('fuzziness', 1))};
        if (fuzziness) {
            query = query.split(/\s+/)
                    .map(str => str.includes('~') ? str : str + '~' + fuzziness).join(' ');
        }

        const results = (await lunr_index).search(query);
        if (!results.length) {
            set_status('No results match your query.');
            return;
        }

        set_status(
            'Search for "' + encodeURIComponent(query) + '" yielded ' + results.length + ' ' +
            (results.length === 1 ? 'result' : 'results') + ':');

        results.forEach(function (result) {
            const dobj = INDEX[parseInt(result.ref)];
            const docstring = dobj.doc;
            // PANDA-docs specific change: remove pandare/ from start of URL
            const url = URLS[dobj.url].replace("pandare/", "") + '#' + dobj.ref;
            console.log(url)
            const pretty_name = dobj.ref + (dobj.func ? '()' : '');
            let text = '';
            if (docstring) {
                text = Object.values(result.matchData.metadata)
                        .filter(({doc}) => doc !== undefined)
                        .map(({doc: {position}}) => {
                            return position.map(([start, length]) => {
                                const PAD_CHARS = 30;
                                const end = start + length;
                                ## TODO: merge overlapping matches
                                return [
                                    start,
                                    (start - PAD_CHARS > 0 ? '…' : '') +
                                    docstring.substring(start - PAD_CHARS, start) +
                                    '<mark>' + docstring.slice(start, end) + '</mark>' +
                                    docstring.substring(end, end + PAD_CHARS) +
                                    (end + PAD_CHARS < docstring.length ? '…' : '')
                                ];
                            });
                        })
                        .flat()
                        .sort(([pos1,], [pos2,]) => pos1 - pos2)
                        .map(([, text]) => text)
                        .join('')
                        .replace(/……/g, '…');
            }

            if (text)
                text = '<div>' + text + '</div>';
            text = '<a href="' + url + '"><code>' + pretty_name + '</code></a>' + text;

            const li = document.createElement('li');
            li.innerHTML = text;
            document.getElementById('search-results').appendChild(li);
        });
    }
</script>
</body>
