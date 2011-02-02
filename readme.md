Django Facebook
====

This app extends the basic Facebook Python SDK with full support of authentification und permission granding in a facebook iframe app

Usage

To use this in your own projects, do the standard:

	python setup.py install


Basic usage:

    graph = facebook.GraphAPI(oauth_access_token)
    profile = graph.get_object("me")
    friends = graph.get_connections("me", "friends")
    graph.put_object("me", "feed", message="I am writing on my wall!")



