"""
Helios URLs for Election related stuff

Ben Adida (ben@adida.net)
"""

from django.conf.urls.defaults import *

from helios.views import *

urlpatterns = patterns('',
    (r'^$', one_election),
    
    # edit election params
    (r'^/edit$', one_election_edit),

    # adding trustees
    (r'^/trustees/$', list_trustees),
    (r'^/trustees/view$', list_trustees_view),
    (r'^/trustees/keygenerator$', election_keygenerator),
    (r'^/trustees/new$', new_trustee),
    (r'^/trustees/delete$', delete_trustee),
    (r'^/trustees/(?P<trustee_uuid>[^/]+)/decrypt-and-prove$', trustee_decrypt_and_prove),
    (r'^/trustees/(?P<trustee_uuid>[^/]+)/upload-decryption$', trustee_upload_decryption),
    
    # election voting-process actions
    (r'^/view$', one_election_view),
    (r'^/result$', one_election_result),
    (r'^/result_proof$', one_election_result_proof),
    (r'^/bboard$', one_election_bboard),

    # construct election
    (r'^/build$', one_election_build),
    (r'^/set_reg$', one_election_set_reg),
    (r'^/save_questions$', one_election_save_questions),
    (r'^/register$', one_election_register),
    (r'^/freeze$', one_election_freeze), # includes freeze_2 as POST target
    
    # computing tally
    (r'^/compute_tally$', one_election_compute_tally),
    (r'^/combine_decryptions$', combine_decryptions),
    
    # casting a ballot before we know who the voter is
    (r'^/cast$', one_election_cast),
    (r'^/cast_confirm$', one_election_cast_confirm),
    (r'^/cast_done$', one_election_cast_done),
    
    # managing voters
    (r'^/voters/$', voter_list),
    (r'^/voters/upload$', voters_upload),
    (r'^/voters/manage$', voters_manage),
    (r'^/voters/email$', voters_email),
    (r'^/voters/(?P<voter_uuid>[^/]+)$', one_voter),
    (r'^/voters/(?P<voter_uuid>[^/]+)/delete$', voter_delete),
    
    # ballots
    (r'^/ballots/$', ballot_list),
    (r'^/ballots/(?P<voter_uuid>[^/]+)/all$', voter_votes),
    (r'^/ballots/(?P<voter_uuid>[^/]+)/last$', voter_last_vote),

)
