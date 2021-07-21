 <%! 
     from pdoc.html_helpers import minify_css 
 %> 
 <%def name="homelink()" filter="minify_css"> 
     .homelink { 
         display: block; 
         font-size: 2em; 
         font-weight: bold; 
         color: #555; 
         padding-bottom: .5em; 
         border-bottom: 1px solid silver; 
     } 
     .homelink:hover { 
         color: inherit; 
     } 
     .homelink img { 
         max-width:20%; 
         max-height: 5em; 
         margin: auto; 
         margin-bottom: .3em; 
     } 
 </%def> 

<!-- Bootstrap core CSS -->
<!--
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet">
-->

<!-- hand-crafted bootstrap navbar -->
<style>
.bg-light {
    background-color: #f8f9fa!important;
}

.navbar {
    position: relative;
    display: -ms-flexbox;
    display: flex;
    -ms-flex-wrap: wrap;
    flex-wrap: wrap;
    -ms-flex-align: center;
    align-items: center;
    -ms-flex-pack: justify;
    justify-content: space-between;
    padding: .5rem 1rem;
}

.navbar-expand-lg {
    -ms-flex-direction: row;
    flex-direction: row;
    -ms-flex-wrap: nowrap;
    flex-wrap: nowrap;
    -ms-flex-pack: start;
    justify-content: flex-start;
}


navbar-light .navbar-brand {
    color: rgba(0,0,0,.9);
}

.navbar-brand {
    display: inline-block;
    padding-top: .3125rem;
    padding-bottom: .3125rem;
    margin-right: 1rem;
    font-size: 1.25rem;
    line-height: inherit;
    white-space: nowrap;
}

.navbar-nav {
    display: -ms-flexbox;
    display: flex;
    -ms-flex-direction: column;
    flex-direction: column;
    padding-left: 0;
    margin-bottom: 0;
    list-style: none;
}

.navbar-expand-lg .navbar-nav {
    -ms-flex-direction: row;
    flex-direction: row;
}

.mr-auto {
    margin-right: auto!important;
}

.navbar-expand-lg .navbar-collapse {
    display: -ms-flexbox!important;
    display: flex!important;
}
.navbar-collapse {
    -ms-flex-preferred-size: 100%;
    flex-basis: 100%;
    -ms-flex-align: center;
    align-items: center;
}
.navbar-light .navbar-brand {
    color: rgba(0,0,0,.9);
}

.navbar a {
    color: #007bff;
    text-decoration: none;
    background-color: transparent;
    -webkit-text-decoration-skip: objects;
}

.navbar-expand-lg .navbar-nav .nav-link {
    padding-right: .5rem;
    padding-left: .5rem;
}

.navbar .navbar-nav {
    margin: 0;
    font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    font-size: 1rem;
    font-weight: 400;
    line-height: 1.5;
    color: #212529;
}

.navbar-light .navbar-nav .active>.nav-link, .navbar-light .navbar-nav .nav-link.active, .navbar-light .navbar-nav .nav-link.show, .navbar-light .navbar-nav .show>.nav-link {
    color: rgba(0,0,0,.9);
}

.navbar-light .navbar-nav .nav-link {
    color: rgba(0,0,0,.5);
}

.nav-link {
    display: block;
    padding: .5rem 1rem;
}
</style>
  
 <style>${homelink()}</style> 
