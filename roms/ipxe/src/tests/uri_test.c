#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ipxe/uri.h>

#define URI_MAX_LEN 1024

struct uri_test {
	const char *base_uri_string;
	const char *relative_uri_string;
	const char *resolved_uri_string;
};

static struct uri_test uri_tests[] = {
	{ "http://www.fensystems.co.uk", "",
	  "http://www.fensystems.co.uk/" },
	{ "http://ipxe.org/wiki/page1", "page2",
	  "http://ipxe.org/wiki/page2" },
	{ "http://ipxe.org/wiki/page1", "../page3",
	  "http://ipxe.org/page3" },
	{ "tftp://192.168.0.1/", "/tftpboot/vmlinuz",
	  "tftp://192.168.0.1/tftpboot/vmlinuz" },
	{ "ftp://the%41nswer%3d:%34ty%32wo@ether%62oot.org:8080/p%41th/foo",
	  "to?%41=b#%43d",
	  "ftp://theAnswer%3d:4ty2wo@ipxe.org:8080/path/to?a=b#cd" },
#if 0
	"http://www.ipxe.org/wiki",
	"mailto:bob@nowhere.com",
	"ftp://joe:secret@insecure.org:8081/hidden/path/to?what=is#this",
#endif
};

static int test_parse_unparse ( const char *uri_string ) {
	char buf[URI_MAX_LEN];
	struct uri *uri = NULL;
	int rc;

	/* Parse and unparse URI */
	uri = parse_uri ( uri_string );
	if ( ! uri ) {
		rc = -ENOMEM;
		goto done;
	}
	unparse_uri ( buf, sizeof ( buf ), uri, URI_ALL );

	/* Compare result */
	if ( strcmp ( buf, uri_string ) != 0 ) {
		printf ( "Unparse of \"%s\" produced \"%s\"\n",
			 uri_string, buf );
		rc = -EINVAL;
		goto done;
	}

	rc = 0;

 done:
	uri_put ( uri );
	if ( rc ) {
		printf ( "URI parse-unparse of \"%s\" failed: %s\n",
			 uri_string, strerror ( rc ) );
	}
	return rc;
}

static int test_resolve ( const char *base_uri_string,
			  const char *relative_uri_string,
			  const char *resolved_uri_string ) {
	struct uri *base_uri = NULL;
	struct uri *relative_uri = NULL;
	struct uri *resolved_uri = NULL;
	char buf[URI_MAX_LEN];
	int rc;

	/* Parse URIs */
	base_uri = parse_uri ( base_uri_string );
	if ( ! base_uri ) {
		rc = -ENOMEM;
		goto done;
	}
	relative_uri = parse_uri ( relative_uri_string );
	if ( ! relative_uri ) {
		rc = -ENOMEM;
		goto done;
	}

	/* Resolve URI */
	resolved_uri = resolve_uri ( base_uri, relative_uri );
	if ( ! resolved_uri ) {
		rc = -ENOMEM;
		goto done;
	}

	/* Compare result */
	unparse_uri ( buf, sizeof ( buf ), resolved_uri, URI_ALL );
	if ( strcmp ( buf, resolved_uri_string ) != 0 ) {
		printf ( "Resolution of \"%s\"+\"%s\" produced \"%s\"\n",
			 base_uri_string, relative_uri_string, buf );
		rc = -EINVAL;
		goto done;
	}

	rc = 0;

 done:
	uri_put ( base_uri );
	uri_put ( relative_uri );
	uri_put ( resolved_uri );
	if ( rc ) {
		printf ( "URI resolution of \"%s\"+\"%s\" failed: %s\n",
			 base_uri_string, relative_uri_string,
			 strerror ( rc ) );
	}
	return rc;
}

int uri_test ( void ) {
	unsigned int i;
	struct uri_test *uri_test;
	int rc;
	int overall_rc = 0;

	for ( i = 0 ; i < ( sizeof ( uri_tests ) /
			    sizeof ( uri_tests[0] ) ) ; i++ ) {
		uri_test = &uri_tests[i];
		rc = test_parse_unparse ( uri_test->base_uri_string );
		if ( rc != 0 )
			overall_rc = rc;
		rc = test_parse_unparse ( uri_test->relative_uri_string );
		if ( rc != 0 )
			overall_rc = rc;
		rc = test_parse_unparse ( uri_test->resolved_uri_string );
		if ( rc != 0 )
			overall_rc = rc;
		rc = test_resolve ( uri_test->base_uri_string,
				    uri_test->relative_uri_string,
				    uri_test->resolved_uri_string );
		if ( rc != 0 )
			overall_rc = rc;
	}

	if ( overall_rc )
		printf ( "URI tests failed: %s\n", strerror ( overall_rc ) );
	return overall_rc;
}
