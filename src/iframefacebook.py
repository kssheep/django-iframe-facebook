import datetime
import logging
import re
import time
import urllib
import urlparse
import settings
import pdb

from facebook import GraphAPI as facebook
import facebook as fb

from django.http import HttpResponse, HttpResponseRedirect
from django.utils.http import urlquote
from django.core.exceptions import ImproperlyConfigured
from django.conf import settings
import time
from django.utils import simplejson
import string
import urllib2
from django.http import QueryDict


###
# helfer zum aufrufen von urls
###
def urlread(url, data=None):
	return urllib2.urlopen(url, data=data).read()
	
	
###
# redirect helfer
###
def get_redirect_path(path):
	return '%s%s' % (settings.FACEBOOK_REDIRECT_URI , path)

def clear_session(session):
	try:
		if settings.DEBUG:
			print "clear session data (fbuid,token,permissons)"
		del session['fbuid']
		del session['access_token']
		del session['expires']
		del session['permissions']
	except:
		pass
	
		
###		
# verarbeitet access token der aus den code den facebook liefert erzeugt wird
###		
def get_access_token_from_code(code, next = settings.FACEBOOK_REDIRECT_URI):
	
	args = {
		'client_id': settings.FACEBOOK_APP_ID,
		'client_secret': settings.FACEBOOK_SECRET_KEY,
		'redirect_uri': next,
		'code': code
	}	
	response = urllib.urlopen(settings.FACEBOOK_TOOKEN_URL + urllib.urlencode(args)).read()
	result = urlparse.parse_qs(response)
	expires= None
	token = None
	if 'expires' in result:
		expires = time.time() + int(result['expires'][0])
	if "access_token" in result:
		token = result['access_token'][0]
	return token, expires


###
# check ob die benoetigten permissions nicht schon vorhanden sind
###
def check_permisson(required_permissions, request):
	
	#koennen mehrere neue permissions benoetigt werden
	required_permissions = string.split(required_permissions,",")
	
	need_permission = None
	if settings.DEBUG:
		print "---------- check permissions ----------"
	
	if "permissions" in request.session:
		
	
		if settings.DEBUG:
			 print "permissions vorhanden  --> vergleichen ob gewuenscht da ist"
		#mehrere permissions vorhanden
		per = request.session["permissions"]
		per = string.split(per,",")
		
		for p in required_permissions:
			if p not in per:
				#es gibt mindestens eine neue permission
				if settings.DEBUG:
					print "es gibt mindestens eine neue permission"
				need_permission = True
				return need_permission
			else:
				if settings.DEBUG:
					print p+ " schon vorhanden"
		
	else:
		need_permission = True
		if settings.DEBUG:
			print "noch keine permissions vorhanden"

	return need_permission


###
# weiterleitung falls keine permissions vorhanden oder wenn user nicht eingeloggt
###
def redirect_auth(next = settings.FACEBOOK_REDIRECT_URI, required_permissions = None):
	args = {}	
	client_id = settings.FACEBOOK_APP_ID	
	if next:
		args['redirect_uri'] = next
	if client_id:
		args['client_id'] = client_id
	
	if required_permissions:	
		args['scope'] = required_permissions		
	
	args['display']="page"
	
	parts = urlparse.urlparse(settings.FACEBOOK_AUTH_URL)
	query = urllib.urlencode(args)
	url = urlparse.urlunparse((
		parts.scheme, #http
		parts.netloc, #graph.facebook.com
		parts.path, #oauth/authorize
		parts.params, #''
		query, #?scope=...&redirect_uri=...
		parts.fragment,
	))
	if settings.DEBUG:
		print "redirect_auth url: " + url
	#logo wird nicht gezeigt redirect erfolgt ueber browser
	if re.search("^https?:\/\/([^\/]*\.)?facebook\.com(:\d+)?", url.lower()):
		return HttpResponse('<script type="text/javascript">\ntop.location.href = "%s";\n</script>' % url)
	else:
		return HttpResponseRedirect(url)
	
	
def check_fb_request(request):
	
	fbuid =  request.REQUEST.get("fb_sig_user",None)
	#print "fbuid: "+str(fbuid)
	if fbuid:
		if "fbuid" in  request.session:
			if request.session["fbuid"] != fbuid:
				if settings.DEBUG:
					print "fbuid hat sich geaendert"
					print "jetzt : "+ str(fbuid)
				clear_session(request.session)
				request.session["fbuid"] = fbuid
		else: 
			if settings.DEBUG:
				print "fbuid noch nicht in session aber aus get"
				print "fbuid jetzt: "+str(fbuid)
			request.session["fbuid"] = fbuid
	else:
		if settings.DEBUG:
			if "fbuid" in  request.session:	 
				print "fbuid ist in session gespeichert"
				print "fbuid ist : "+ str(request.session["fbuid"])
			else:
				print "gar keine fbuid vorhanden"
		
	per = request.REQUEST.get("fb_sig_ext_perms",None)
	if per:
		if "permissions" in  request.session:
			if request.session["permissions"] != per:
				if settings.DEBUG:
					print "permissions haben sich geaendert"
					print "jetzt : "+ str(per)
				request.session["permissions"] = per
		else: 
			if settings.DEBUG:
				print "permissions noch nicht in session aber aus get"
				print "permissions jetzt: "+str(per)
			request.session["permissions"] = per
	else:
		if settings.DEBUG:
			if "permissions" in  request.session:	 
				print "permissions sind in session gespeichert"
				print "permissions sind : "+ str(request.session["permissions"])
			else:
				print "gar keine permissions vorhanden"
				print "user nicht angemeldet oder auf seite die keine auth erfordert"	


###
# decorater der ueberprueft ob derjenige bei facebook eingeloggt ist, bzw ob ein gueltiger access token vorliegt
###
def require_login(permissions=None):


	def decorator(view):
		def newview(request, *args, **kwargs):
			
 			check_fb_request(request)			
 						
			
			if "error_reason" in request.GET:
				if settings.DEBUG:
					print "raus weil user kein zugriff auf seine daten erlaubt"
				return HttpResponse('<script type="text/javascript">\ntop.location.href = "%s";\n</script>' % settings.FACEBOOK_REDIRECT_URI)
			
			if "expires" in request.session:
				if settings.DEBUG:
					print "token expires in: "  + str(time.time()-request.session["expires"])
				if request.session["expires"] < time.time():
					if settings.DEBUG:
						print "token has expired"
					try:
						del request.session['access_token']
						del request.session['expires']
					except:
						if settings.DEBUG:
							print "token oder expires war nicht in session"
						pass
					return redirect_auth(next=get_redirect_path(request.path),required_permissions=permissions)
		
			#authcode von einer anwendung
			if 'code' in request.GET:
				print request
				if settings.DEBUG:
					print "access token aus code"
				a,e = get_access_token_from_code(request.GET["code"],next=get_redirect_path(request.path))
				if a:
					request.session["access_token"] = a
					request.session["expires"] =  e
					request.graph = facebook(a)
					request.fbuid = request.REQUEST.get("fb_sig_user",None)
					request.session["fbuid"] = request.fbuid 
					request.session["permissions"] = request.REQUEST.get("fb_sig_ext_perms",None)
					
					#agent = request.META['HTTP_USER_AGENT']					
					#if agent.find("Safari")>0 and agent.find("Version")>0:
					#	return HttpResponse('<script type="text/javascript">\ntop.location.href = "%s";\n</script>' % FACEBOOK_REDIRECT_URI + request.path)
				else:
				#user hat f5 gedruckt und ein alter code wurde verwendet
				#konnte kein token erzeugt werden
					return redirect_auth(next=get_redirect_path(request.path),required_permissions=permissions)
					
				#request.GET = {}
			
				
			if "access_token" not in request.session:
				if settings.DEBUG:
					print "noch kein token in der session --> user hat seite direkt aufgerufen"
				return redirect_auth(next=get_redirect_path(request.path),required_permissions=permissions)
				 
			#man braucht neue permissions
			if permissions:

				if settings.DEBUG:
					print "neue permissions notwendig: "+permissions
				per = request.session.get("permissions",None)
				if per:
					print per
					new = check_permisson(permissions,request)
					if new:
						return redirect_auth(next=get_redirect_path(request.path),required_permissions=permissions)
				else:
					return redirect_auth(next=get_redirect_path(request.path),required_permissions=permissions)
			
			#access token muesst jetzt vorliegen  
			if settings.DEBUG:
				print "token in session: "+request.session["access_token"] 
			try:
			
				return view(request, *args, **kwargs)
				
			except fb.GraphAPIError as er:
				 if settings.DEBUG:
					 print er.args
				 if str(er)=='Error validating access token.':
					 clear_session(request.session)
					 return HttpResponseRedirect(request.path)
					 
				 else:
					 return HttpResponseRedirect("/") 
				
		return newview
	return decorator		



###
# fuegt jeden request ein facebook objekt hinzu
# + speichert die facbookuserid in einer session
# + speichert die permissions eines users in einer session
###	
class FacebookMiddleware(object):

 
	def process_request(self, request):
			
		request.fbuid = request.session.get("fbuid",None)			
		if 'access_token' in request.session:
			fb=facebook(request.session["access_token"])
			request.graph = fb
			#request.session['graph'] = fb
			if settings.DEBUG:
				print "graph erzeugt in request"
			#return request
		else:
			if settings.DEBUG:
				print "kein token in middleware"
		
		
		
		
		
#http://djangosnippets.org/snippets/1540/	
# + safari fall back
class CookielessSessionMiddleware(object):
	def __init__(self):

		self._re_links = re.compile(r'<a(?P<pre_href>[^>]*?)href=["\'](?P<in_href>[^"\']*?)(?P<anchor>#\S+)?["\'](?P<post_href>[^>]*?)>', re.I)
		self._re_forms = re.compile('</form>', re.I)

	def _prepare_url(self, url):
		patt = None
		if url.find('?') == -1:
			patt = '%s?'
		else:
			patt = '%s&amp;'
		return patt % (url,)

	def process_request(self, request):
		agent = request.META['HTTP_USER_AGENT']					
		if agent.find("Safari")>0 and agent.find("Version")>0:
		
			if not request.COOKIES.has_key('sessionid'):
				value = None
				if hasattr(request, 'POST') and request.POST.has_key('sessionid'):
					value = request.POST['sessionid']
				elif hasattr(request, 'GET') and request.GET.has_key('sessionid'):
					value = request.GET['sessionid']
				if value:
					request.COOKIES['sessionid'] = value		

	def process_response(self, request, response):
		agent = request.META['HTTP_USER_AGENT']					
		if agent.find("Safari")>0 and agent.find("Version")>0:
		
			if not request.path.startswith("/admin")  and response.cookies.has_key('sessionid'):
				try:
					sessionid = response.cookies['sessionid'].coded_value
					if type(response) is HttpResponseRedirect:
	
						if not sessionid: sessionid = ""
						redirect_url = [x[1] for x in response.items() if x[0] == "Location"][0]
						redirect_url = self._prepare_url(redirect_url)
						return HttpResponseRedirect('%ssessionid=%s' % (redirect_url,sessionid,)) 
	
	
					def new_url(m):
						anchor_value = ""
						if m.groupdict().get("anchor"): anchor_value = m.groupdict().get("anchor")
						return_str = '<a%shref="%ssessionid=%s%s"%s>' % \
							 (m.groupdict()['pre_href'],
							 self._prepare_url(m.groupdict()['in_href']),
							 sessionid,
							 anchor_value,
							 m.groupdict()['post_href'])
						return return_str								 
					response.content = self._re_links.sub(new_url, response.content)
	
	
					repl_form = '<div><input type="hidden" name="sessionid" value="%s" /></div>' + \
						'</form>'
					repl_form = repl_form % (sessionid,)
					response.content = self._re_forms.sub(repl_form, response.content)
	
					return response	
				except:
		
					return response
			else:
				return response
		else:
			#fix fuer ie7 und 8 das cookies im iframe funktionieren
			response["P3P"] = 'CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"'
			return response		
		
		
		
		
		
		
		
		
		
		
		
		
		