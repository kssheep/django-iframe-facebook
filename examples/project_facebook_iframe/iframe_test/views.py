# Create your views here.
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.http import HttpResponse
import iframefacebook as iframe


def index(request):
	return render_to_response("index.html",RequestContext(request))
	
@iframe.require_login()	
def authorization(request):
	profile = request.graph.get_object("me")
	return render_to_response("auth.html",{"p":profile,},RequestContext(request))
	
@iframe.require_login(permissions="read_stream")
def permissions(request):
	stream = request.graph.get_connections("me","feed")
	stream = stream["data"]
	return render_to_response("perm.html",{"stream":stream,},RequestContext(request))
