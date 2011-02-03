Django iFrame Facebook
====

This app extends the basic Facebook Python SDK with full support of authentication and permission granting in a facebook iframe app



Usage

To use this in your own projects, do the standard:

	python setup.py install

The following settings have to be done in your settings.py
	
	#facebook keys
	FACEBOOK_API_KEY = 'your key'
	FACEBOOK_SECRET_KEY = 'your key'
	FACEBOOK_APP_ID = 'your id'
	
	#url with no auth required. user gets redirect to this url if he doesn't allow our app some permissions
	FACEBOOK_REDIRECT_URI = 'http://apps.facebook.com/yourapp' 
	
	FACEBOOK_AUTH_URL = 'https://graph.facebook.com/oauth/authorize'
	FACEBOOK_TOOKEN_URL = 'https://graph.facebook.com/oauth/access_token?'


	MIDDLEWARE_CLASSES = (
	    'django.middleware.common.CommonMiddleware',
		'iframefacebook.CookielessSessionMiddleware',  #safari fallback (problem with cookies in iframes)
	    'django.contrib.sessions.middleware.SessionMiddleware',
	    'django.contrib.auth.middleware.AuthenticationMiddleware',
		'iframefacebook.FacebookMiddleware', #required for easier access to the facebook graph
	)


to access the graph in a view use:

	import iframefacebook
	
	@iframefacebook.require_login()	
	def authorization(request):
		profile = request.graph.get_object("me")
		return render_to_response("auth.html",{"p":profile,},RequestContext(request))

	@iframefacebook.require_login(permissions="read_stream,user_events")
	def permissions(request):
		stream = request.graph.get_connections("me","feed")
		stream = stream["data"]
		return render_to_response("perm.html",{"stream":stream,},RequestContext(request))
	


at the moment there must be a few special settings on facebook for your app:

	OAuth 2.0 for Canvas	disabled
	POST for Canvas			disabled	


to use the example project run python manage.py syncdb at the beginning