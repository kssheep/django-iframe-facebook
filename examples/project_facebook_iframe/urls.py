from django.conf.urls.defaults import *

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
	(r'^$', 'project_facebook_iframe.iframe_test.views.index'),
	url(r'^auth/$', 'project_facebook_iframe.iframe_test.views.authorization', name='auth'),
    url(r'^per/$', 'project_facebook_iframe.iframe_test.views.permissions', name='per'),
	# Example:
    # (r'^project_facebook_iframe/', include('project_facebook_iframe.foo.urls')),

    # Uncomment the admin/doc line below and add 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # (r'^admin/', include(admin.site.urls)),
)
