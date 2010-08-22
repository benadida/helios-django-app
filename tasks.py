"""
Celery queued tasks for Helios

2010-08-01
ben@adida.net
"""

from celery.decorators import task

from models import *
from view_utils import render_template_raw
import signals

import copy


@task()
def cast_vote_verify_and_store(cast_vote_id, status_update_message=None):
    cast_vote = CastVote.objects.get(id = cast_vote_id)
    result = cast_vote.verify_and_store()

    voter = cast_vote.voter
    election = voter.election
    user = voter.user

    if result:
        # send the signal
        signals.vote_cast.send(sender=election, election=election, user=user, voter=voter, cast_vote=cast_vote)
        
        if status_update_message and user.can_update_status():
            from views import get_election_url

            user.update_status(status_update_message)
    else:
        # FIXME: do something about a bad vote
        pass
    
@task()
def voters_email(election_id, subject_template, body_template, extra_vars={}):
    election = Election.objects.get(id = election_id)
    for voter in election.voter_set.all():
        single_voter_email.delay(voter.uuid, subject_template, body_template, extra_vars)

@task()
def voters_notify(election_id, notification_template, extra_vars={}):
    election = Election.objects.get(id = election_id)
    for voter in election.voter_set.all():
        single_voter_notify.delay(voter.uuid, notification_template, extra_vars)

@task()
def single_voter_email(voter_uuid, subject_template, body_template, extra_vars={}):
    voter = Voter.objects.get(uuid = voter_uuid)

    the_vars = copy.copy(extra_vars)
    the_vars.update({'voter' : voter})

    subject = render_template_raw(None, subject_template, the_vars)
    body = render_template_raw(None, body_template, the_vars)

    voter.user.send_message(subject, body)

@task()
def single_voter_notify(voter_uuid, notification_template, extra_vars={}):
    voter = Voter.objects.get(uuid = voter_uuid)

    the_vars = copy.copy(extra_vars)
    the_vars.update({'voter' : voter})

    notification = render_template_raw(None, notification_template, the_vars)

    voter.user.send_notification(notification)

@task()
def election_compute_tally(election_id):
    election = Election.objects.get(id = election_id)
    election.compute_tally()
    
    election_notify_admin.delay(election_id = election_id,
                                subject = "encrypted tally computed",
                                body = """
The encrypted tally for election %s has been computed.

--
Helios
""" % election.name)
                                
    
    if election.has_helios_trustee():
        tally_helios_decrypt.delay(election_id = election.id)

@task()
def tally_helios_decrypt(election_id):
    election = Election.objects.get(id = election_id)
    election.helios_trustee_decrypt()
    election_notify_admin.delay(election_id = election_id,
                                subject = 'Helios Decrypt',
                                body = """
Helios has decrypted its portion of the tally
for election %s.

--
Helios
""" % election.name)

@task()
def voter_file_process(voter_file_id):
    voter_file = VoterFile.objects.get(id = voter_file_id)
    voter_file.process()
    election_notify_admin.delay(election_id = voter_file.election.id, 
                                subject = 'voter file processed',
                                body = """
Your voter file upload for election %s
has been processed.

%s voters have been created.

--
Helios
""" % (voter_file.election.name, voter_file.num_voters))

@task()
def election_notify_admin(election_id, subject, body):
    election = Election.objects.get(id = election_id)
    election.admin.send_message(subject, body)
