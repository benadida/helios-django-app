# -*- coding: utf-8 -*-
from django.conf.urls.defaults import *

from views import *

urlpatterns = patterns('',
  (r'^$', home),
  (r'^about$', about),

  # election
  (r'^elections/params$', election_params),
  (r'^elections/verifier$', election_verifier),
  (r'^elections/single_ballot_verifier$', election_single_ballot_verifier),
  (r'^elections/new$', election_new),
  
  (r'^elections/(?P<election_id>[^/]+)', include('helios.election_urls')),
  
)
