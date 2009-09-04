# -*- coding: utf-8 -*-
"""
Helios Django Views

Ben Adida (ben@adida.net)
"""

from django.core.urlresolvers import reverse
from django.core.mail import send_mail
from django.http import *
from google.appengine.ext import db
from mimetypes import guess_type

import csv

from crypto import algs, electionalgs
from crypto import utils as cryptoutils
from helios import utils as helios_utils
from view_utils import *
from auth.security import *

from security import *
from auth.security import get_user

import uuid, datetime
import counters

from models import *

import forms, signals

# Parameters for everything
ELGAMAL_PARAMS = algs.ElGamal()
#ELGAMAL_PARAMS.p = 169989719781940995935039590956086833929670733351333885026079217526937746166790934510618940073906514429409914370072173967782198129423558224854191320917329420870526887804017711055077916007496804049206725568956610515399196848621653907978580213217522397058071043503404700268425750722626265208099856407306527012763L
#ELGAMAL_PARAMS.q = 84994859890970497967519795478043416964835366675666942513039608763468873083395467255309470036953257214704957185036086983891099064711779112427095660458664710435263443902008855527538958003748402024603362784478305257699598424310826953989290106608761198529035521751702350134212875361313132604049928203653263506381L
#ELGAMAL_PARAMS.g = 68111451286792593845145063691659993410221812806874234365854504719057401858372594942893291581957322023471947260828209362467690671421429979048643907159864269436501403220400197614308904460547529574693875218662505553938682573554719632491024304637643868603338114042760529545510633271426088675581644231528918421974L

# trying new ones from OlivierP
ELGAMAL_PARAMS.p = 16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071L
ELGAMAL_PARAMS.q = 61329566248342901292543872769978950870633559608669337131139375508370458778917L
ELGAMAL_PARAMS.g = 14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533L


# single election server? Load the single electionfrom models import Election
from django.conf import settings

# a helper function
def get_election_url(election):
  return settings.URL_HOST + reverse(one_election_view, args=[election.uuid])  

# simple static views
def home(request):
  user = get_user(request)
  if user:
    elections = Election.get_by_user_as_admin(user)
  else:
    elections = []
  
  return render_template(request, "index", {'elections' : elections})
  
def learn(request):
  return render_template(request, "learn")
  
def faq(request):
  return render_template(request, "faq")
  
def about(request):
  return HttpResponse(request, "about")
    
##
## General election features
##

@json
def election_params(request):
  return ELGAMAL_PARAMS.toJSONDict()

def election_verifier(request):
  return render_template(request, "tally_verifier")

def election_single_ballot_verifier(request):
  return render_template(request, "ballot_verifier")

@election_view()
def election_keygenerator(request, election):
  """
  A key generator with the current params, like the trustee home but without a specific election.
  """
  eg_params_json = utils.to_json(ELGAMAL_PARAMS.toJSONDict())
  return render_template(request, "election_keygenerator", {'eg_params_json': eg_params_json})

@login_required
def election_new(request):
  if not can_create_election(request):
    return HttpResponseForbidden('only the admin can create an election')
    
  error = None
  
  if request.method == "GET":
    election_form = forms.ElectionForm()
  else:
    election_form = forms.ElectionForm(request.POST)
    
    if election_form.is_valid():
      # create the election obj
      election_params = dict(election_form.cleaned_data)
      
      # is the short name valid
      if helios_utils.urlencode(election_params['short_name']) == election_params['short_name']:      
        election_params['uuid'] = str(uuid.uuid1())
        election_params['cast_url'] = settings.URL_HOST + reverse(one_election_cast, args=[election_params['uuid']])
      
        # registration starts closed
        election_params['openreg'] = False

        user = get_user(request)
        election_params['admin'] = user
        # election_params['api_client'] = get_api_client(request)

        election, created_p = Election.get_or_create(**election_params)
      
        if created_p:
          counters.increment(GLOBAL_COUNTER_ELECTIONS)
          return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
        else:
          error = "An election with short name %s already exists" % election_params['short_name']
      else:
        error = "No special characters allowed in the short name."
    
  return render_template(request, "election_new", {'election_form': election_form, 'error': error})
  
@election_view()
@json
def one_election(request, election):
  return election.toJSONDict()

@election_view()
def one_election_view(request, election):
  user = get_user(request)
  admin_p = user and (user == election.admin)
  
  notregistered = False
  
  if user:
    voter = Voter.get_by_election_and_user(election, user)
    
    if voter:
      # cast any votes?
      votes = CastVote.get_by_election_and_voter(election, voter)
    else:
      votes = None
      notregistered = True
  else:
    voter = None
    votes = None
    
  return render_template(request, 'election_view', {'election' : election, 'admin_p': admin_p, 'user': user, 'voter': voter, 'votes': votes, 'notregistered': notregistered, 'email_voters': helios.VOTERS_EMAIL})
  
##
## Trustees and Public Key
##
## As of July 2009, there are always trustees for a Helios election: one trustee is acceptable, for simple elections.
##
@json
@election_view()
def list_trustees(request, election):
  trustees = Trustee.get_by_election(election)
  return [t.toJSONDict() for t in trustees]
  
@election_view()
def list_trustees_view(request, election):
  trustees = Trustee.get_by_election(election)
  return render_template(request, 'list_trustees', {'election': election, 'trustees': trustees})
  
@election_admin(frozen=False)
def new_trustee(request, election):
  if request.method == "GET":
    return render_template(request, 'new_trustee', {'election' : election})
  else:
    # get the public key and the hash, and add it
    public_key_and_proof = utils.from_json(request.POST['public_key_json'])
    public_key = algs.EGPublicKey.fromJSONDict(public_key_and_proof['public_key'])
    pok = algs.DLogProof.fromJSONDict(public_key_and_proof['pok'])
    name = request.POST['name']
    
    # verify the pok
    if not public_key.verify_sk_proof(pok, algs.DLog_challenge_generator):
      raise Exception("bad pok for this public key")
    
    public_key_hash = utils.hash_b64(utils.to_json(public_key.toJSONDict()))
    
    trustee = Trustee(uuid = str(uuid.uuid1()), public_key = public_key, public_key_hash = public_key_hash, pok = pok, election = election, name=name)
    trustee.put()
    return HttpResponseRedirect(reverse(list_trustees_view, args=[election.uuid]))
    
@election_admin()
def delete_trustee(request, election):
  trustee = Trustee.get_by_election_and_uuid(election, request.GET['uuid'])
  trustee.delete()
  return HttpResponseRedirect(reverse(list_trustees_view, args=[election.uuid]))
  
  
@election_view(frozen=True)
def one_election_cast(request, election):
  user = get_user(request)    
  encrypted_vote = request.POST['encrypted_vote']
  request.session['encrypted_vote'] = encrypted_vote
  return HttpResponseRedirect(reverse(one_election_cast_confirm, args=[election.uuid]))

@election_view(frozen=True)
def one_election_cast_confirm(request, election):
  user = get_user(request)    

  if user:
    voter = Voter.get_by_election_and_user(election, user)
  else:
    voter = None
    
  # tallied election, no vote casting
  if election.encrypted_tally or election.result:
    return render_template(request, 'election_tallied', {'election': election})
    
  encrypted_vote = request.session['encrypted_vote']
  vote_fingerprint = cryptoutils.hash_b64(encrypted_vote)

  # if this user is a voter, prepare some stuff
  if voter:
    # prepare the vote to cast
    cast_vote_params = {
      'vote' : electionalgs.EncryptedVote.fromJSONDict(utils.from_json(encrypted_vote)),
      'voter' : voter,
      'vote_hash': vote_fingerprint,
      'cast_at': datetime.datetime.utcnow(),
      'election': election
    }
    
    cast_vote = CastVote(**cast_vote_params)
  else:
    cast_vote = None
    
  if request.method == "GET":
    if voter:
      past_votes = CastVote.get_by_election_and_voter(election, voter)
      if len(past_votes) == 0:
        past_votes = None
    else:
      past_votes = None

    if cast_vote:
      # check for issues
      issues = cast_vote.issues(election)
    else:
      issues = None

    return render_template(request, 'election_cast_confirm', {'election' : election, 'vote_fingerprint': vote_fingerprint, 'past_votes': past_votes, 'issues': issues, 'voter' : voter})
      
  if request.method == "POST":
    check_csrf(request)
    
    # if user is not logged in or user is not a voter
    # bring back to the confirmation page to let him know
    if not (user!=None and voter!=None):
      return HttpResponseRedirect(reverse(one_election_cast_confirm, args=[election.uuid]))
    
    # verify the vote
    if cast_vote.vote.verify(election):
      # store it
      voter.store_vote(cast_vote)
    else:
      return HttpResponse("vote does not verify: " + utils.to_json(cast_vote.vote.toJSONDict()))
    
    # remove the vote from the store
    del request.session['encrypted_vote']
    
    # send the signal
    signals.vote_cast.send(sender=election, election=election, user=user, cast_vote=cast_vote)
    
    return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
  
@election_view()
@json
def one_election_result(request, election):
  return election.result

@election_view()
@json
def one_election_result_proof(request, election):
  return election.result_proof
  
@election_view(frozen=True)
def one_election_bboard(request, election):
  """
  UI to show election bboard
  """
  after = request.GET.get('after', None)
  limit = int(request.GET.get('limit', 50))

  # if there's a specific voter
  if request.GET.has_key('q'):
    # FIXME: figure out the voter by voter_id
    voters = []
  else:
    # load a bunch of voters
    voters = Voter.get_by_election(election, after=request.GET.get('after', None), limit=limit+1)
    
  more_p = len(voters) > limit
  if more_p:
    voters = voters[0:limit]
    next_after = voters[limit-1].voter_id
  else:
    next_after = None
    
  return render_template(request, 'election_bboard', {'election': election, 'voters': voters, 'next_after': next_after,
                'voter_id': request.GET.get('voter_id', '')})
    
@election_admin(frozen=False)
def voter_delete(request, election, voter_uuid):
  voter = Voter.get_by_election_and_uuid(election, voter_uuid)
  if voter:
    voter.delete()
    
  return HttpResponseRedirect(reverse(voters_manage, args=[election.uuid]))

@election_admin(frozen=False)
def one_election_set_reg(request, election):
  """
  Set whether this is open registration or not
  """
  open_p = bool(int(request.GET['open_p']))
  election.openreg = open_p
  election.save()
  
  return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))

@election_admin()
def one_election_archive(request, election, admin, api_client):
  
  archive_p = request.GET.get('archive_p', True)
  
  if bool(int(archive_p)):
    election.archived_at = datetime.datetime.utcnow()
  else:
    election.archived_at = None
    
  storage.election_update(election)

  if get_user(request):
    return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
  else:
    return SUCCESS

@election_admin(frozen=False)
def one_election_build(request, election):
  questions_json = utils.to_json(election.questions)
  
  return render_template(request, 'election_build', {'election': election, 'questions_json' : questions_json})
  
@election_view()
def one_election_register(request, election):
  if not election.openreg:
    return HttpResponseForbidden('registration is closed for this election')
    
  check_csrf(request)
    
  user = get_user(request)
  voter = Voter.get_by_election_and_user(election, user)
  
  if not voter:
    voter_uuid = str(uuid.uuid1())
    voter = Voter(uuid= voter_uuid, voter_type = user.user_type, voter_id = user.user_id, election = election)
    
    if election.use_voter_aliases:
      voter.alias = "V" + str(election.num_voters+1)
      
    voter.put()

  return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))

@election_admin(frozen=False)
def one_election_save_questions(request, election):
  check_csrf(request)
  
  election.questions = utils.from_json(request.POST['questions_json']);
  election.save()

  # always a machine API
  return SUCCESS

@election_admin(frozen=False)
def one_election_freeze(request, election):
  # figure out the number of questions and trustees
  issues = []
  if election.questions == None or len(election.questions) == 0:
    issues.append("no questions")
  
  trustees = Trustee.get_by_election(election)
  if len(trustees) == 0:
    issues.append("no trustees")
    
  if request.method == "GET":
    return render_template(request, 'election_freeze', {'election': election, 'issues' : issues, 'issues_p' : len(issues) > 0})
  else:
    check_csrf(request)
    
    election.freeze()

    if get_user(request):
      return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
    else:
      return SUCCESS    

@election_admin(frozen=True)
def one_election_compute_tally(request, election):
  if election.tally_type != "homomorphic":
    return HttpResponseRedirect(reverse(one_election_view,args=[election.election_id]))

  if request.method == "GET":
    return render_template(request, 'election_compute_tally', {'election': election})
  
  check_csrf(request)
    
  voters = Voter.get_by_election(election, cast=True)

  tally = election.init_tally()
  
  # get the votes and set the public key
  votes = [v.vote for v in voters]
  tally.add_vote_batch(votes, verify_p=False)

  election.encrypted_tally = tally
  election.save()
  
  if get_user(request):
    return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
  else:
    return SUCCESS    

@election_view()
def trustee_decrypt_and_prove(request, election, trustee_uuid):
  if election.tally_type != "homomorphic" or election.encrypted_tally == None:
    return HttpResponseRedirect(reverse(one_election_view,args=[election.election_id]))
    
  trustee = Trustee.get_by_election_and_uuid(election, trustee_uuid)

  return render_template(request, 'trustee_decrypt_and_prove', {'election': election, 'trustee': trustee})
  
@election_view(frozen=True)
def trustee_upload_decryption(request, election, trustee_uuid):
  if election.tally_type != "homomorphic" or election.encrypted_tally == None:
    return HttpResponseRedirect(reverse(one_election_view,args=[election.election_id]))

  trustee = Trustee.get_by_election_and_uuid(election, trustee_uuid)

  # verify the decryption factors
  trustee.decryption_factors = utils.from_json(request.POST['decryption_factors'])
  trustee.decryption_proofs = utils.from_json(request.POST['decryption_proofs'])
  if trustee.verify_decryption_proofs():
    trustee.save()
    return SUCCESS
  else:
    return FAILURE
  
@election_admin(frozen=True)
def combine_decryptions(request, election):
  election.combine_decryptions()
  election.save()
  
  return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))

@election_admin(frozen=True)
def one_election_set_result_and_proof(request, election):
  if election.tally_type != "homomorphic" or election.encrypted_tally == None:
    return HttpResponseRedirect(reverse(one_election_view,args=[election.election_id]))

  # FIXME: check csrf
  
  election.result = utils.from_json(request.POST['result'])
  election.result_proof = utils.from_json(request.POST['result_proof'])
  election.save()

  if get_user(request):
    return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
  else:
    return SUCCESS
  
  
@election_admin()
def voters_manage(request, election):
  """
  Show the list of voters
  """
  after = request.GET.get('after', None)
  limit = int(request.GET.get('limit', 200))

  voters = Voter.get_by_election(election, after=request.GET.get('after', None), limit=limit+1)
  
  return render_template(request, 'voters_manage', {'election': election, 'voters': voters, 'upload_p': helios.VOTERS_UPLOAD})
  
@election_admin(frozen=False)
def voters_upload(request, election):
  """
  Upload a CSV of password-based voters with
  voter_type, voter_id, email, name
  
  name and email are needed only if voter_type is static
  """
  if request.method == "POST":
    voters_csv_lines = request.POST['voters_csv'].split("\n")
    reader = csv.reader(voters_csv_lines)

    voter_alias = election.num_voters + 1
    
    for voter in reader:

      # bad line
      if len(voter) < 2:
        continue

      voter_type = voter[0]
      voter_id = voter[1]
      name = voter_id
      email = voter_id
      
      if len(voter) > 2:
        email = voter[2]
      
      if len(voter) > 3:
        name = voter[3]
        
      if voter_type == 'password':
        # create the user
        user = User.get_or_create(user_type=voter_type, user_id=voter_id, info = {'password': helios_utils.random_string(10), 'email': email, 'name': name})
        user.put()
      
      # create the voter
      voter_uuid = str(uuid.uuid1())
      voter = Voter(uuid= voter_uuid, voter_type = voter_type, voter_id = voter_id, name = name, election = election)

      if election.use_voter_aliases:
        voter.alias = "V" + str(voter_alias)
        voter_alias += 1

      voter.put()
    
  return HttpResponseRedirect(reverse(voters_manage, args=[election.uuid]))

@election_admin(frozen=True)
def voters_email(request, election):
  if not helios.VOTERS_EMAIL:
    return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
    
  if request.method == "GET":
    email_form = forms.EmailVotersForm()
  else:
    email_form = forms.EmailVotersForm(request.POST)
    
    if email_form.is_valid():
      
      # go through all voters
      # FIXME for large # of voters
      voters = Voter.get_by_election(election)
      
      for voter in voters:
        if voter.voter_type != 'password':
          continue
        
        user = voter.user
        body = """
Dear %s,
""" % voter.name

        body += email_form.cleaned_data['body'] + """
        
Election URL:  %s
Your username: %s
Your password: %s""" % (get_election_url(election), user.user_id, user.info['password'])

        if election.use_voter_aliases:
          body+= """
Your voter alias: %s

In order to protect your privacy, this election is configured to never display your username,
name, or email address to the public. Instead, the bulletin board will only display your alias.

""" % voter.alias

        body += """

--
Helios
"""

        send_mail(email_form.cleaned_data['subject'], body, settings.SERVER_EMAIL, ["%s <%s>" % (user.info['name'], user.info['email'])], fail_silently=False)
      
      
      return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
    
  return render_template(request, "voters_email", {'email_form': email_form})    

# Individual Voters
@election_view()
@json
def voter_list(request, election):
  # normalize limit
  limit = int(request.GET.get('limit', 500))
  if limit > 500: limit = 500
    
  voters = Voter.get_by_election(election, after=request.GET.get('after',None), limit= limit)
  return [v.toJSONDict() for v in voters]
  
@election_view()
@json
def one_voter(request, election, voter_uuid):
  """
  View a single voter's info as JSON.
  """
  voter = Voter.get_by_election_and_uuid(election, voter_uuid)
  return voter.toJSONDict()  

@election_view()
@json
def voter_votes(request, election, voter_uuid):
  """
  all cast votes by a voter
  """
  voter = Voter.get_by_election_and_uuid(election, voter_uuid)
  votes = CastVote.get_by_election_and_voter(election, voter)
  return [v.toJSONDict()  for v in votes]

@election_view()
@json
def voter_last_vote(request, election, voter_uuid):
  """
  all cast votes by a voter
  """
  voter = Voter.get_by_election_and_uuid(election, voter_uuid)
  return voter.last_cast_vote().toJSONDict()

##
## cast ballots
##

@election_view()
@json
def ballot_list(request, election):
  voters = Voter.get_by_election(election, cast=True)
  return [v.last_cast_vote().toJSONDict(include_vote=False) for v in voters]


  

