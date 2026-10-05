import json
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from pydantic import BaseModel, Field
from app.auth import administrator, current_user, get_db
from app.models import EndpointAgent, utcnow
from app.analytic_models import BiometricBinding, BiometricConsent, BiometricProfile, BiometricSample
from app.biometrics import permitted, enroll
from app.privacy import audit, pseudonym, setting

router = APIRouter(prefix='/api/biometrics', tags=['behavioral biometrics'])


class BindingInput(BaseModel):
    subject: str = Field(min_length=1, max_length=120, pattern=r'\S')
    enabled: bool = True


@router.put('/bindings/{agent_id}')
def bind(agent_id: int, data: BindingInput, user=Depends(administrator), db=Depends(get_db)):
    if not db.get(EndpointAgent, agent_id): raise HTTPException(404, 'Agent not found')
    row=db.get(BiometricBinding,agent_id)
    if row is None: row=BiometricBinding(agent_id=agent_id,subject=data.subject); db.add(row)
    if row.subject != data.subject:
        # Rebinding requires fresh consent; previous operator approval never transfers.
        db.add(BiometricConsent(agent_id=agent_id,granted=False,expires_at=utcnow()))
    row.subject=data.subject; row.enabled=data.enabled
    audit(db,user.username,'biometric_binding_changed',agent_id=agent_id,subject=data.subject,enabled=data.enabled); db.commit()
    return {'agent_id':agent_id,'subject':row.subject,'enabled':row.enabled}


@router.get('/agent/status')
def agent_status(request: Request, db=Depends(get_db)):
    from app.routers.agents import _agent_from_token
    agent=_agent_from_token(request,db); binding=db.get(BiometricBinding,agent.id)
    return {'permitted':permitted(db,agent.id),'configured':bool(binding and binding.enabled),
            'purpose':'Compare aggregate typing timing and mouse movement summaries to a trusted enrollment baseline. Characters and absolute coordinates are not recorded.'}


class ConsentInput(BaseModel):
    granted: bool


@router.post('/agent/consent',status_code=201)
def consent(data:ConsentInput,request:Request,db=Depends(get_db)):
    from app.routers.agents import _agent_from_token
    agent=_agent_from_token(request,db)
    if not db.get(BiometricBinding,agent.id): raise HTTPException(409,'Administrator binding required before consent')
    db.add(BiometricConsent(agent_id=agent.id,granted=data.granted,expires_at=utcnow()+timedelta(days=30)))
    audit(db,f'agent:{agent.id}','biometric_consent_granted' if data.granted else 'biometric_consent_withdrawn'); db.commit()
    return {'granted':data.granted}


class EnrollmentInput(BaseModel):
    subject: str = Field(min_length=1,max_length=120)
    sample_ids:list[int]=Field(min_length=5,max_length=100)
    threshold:float=Field(default=3,ge=1,le=10,allow_inf_nan=False)
    trusted_identity_confirmed:bool=False


@router.post('/enroll',status_code=201)
def enrollment(data:EnrollmentInput,user=Depends(administrator),db=Depends(get_db)):
    if not data.trusted_identity_confirmed: raise HTTPException(422,'Confirm sample identity using independent authentication before enrollment')
    row=enroll(db,data.subject,data.sample_ids,user.username,data.threshold)
    audit(db,user.username,'biometric_enrolled',subject=data.subject,sample_ids=data.sample_ids,threshold=data.threshold); db.commit()
    return {'subject':row.subject,'metrics':list(json.loads(row.baseline)),'threshold':row.threshold}


@router.get('/samples')
def samples(subject:str='',limit:int=Query(50,ge=1,le=100),user=Depends(administrator),db=Depends(get_db)):
    query=db.query(BiometricSample)
    if subject: query=query.filter_by(subject=subject)
    return [{'id':row.id,'subject':row.subject,'agent_id':row.agent_id,'status':row.status,'distance':row.distance,
             'metrics':json.loads(row.metrics),'alert_id':row.alert_id} for row in query.order_by(BiometricSample.id.desc()).limit(limit)]


@router.get('/summary')
def summary(user=Depends(current_user),db=Depends(get_db)):
    settings=setting(db)
    rows=db.query(BiometricSample).order_by(BiometricSample.id.desc()).limit(100).all()
    return {'samples':[{'subject':pseudonym(settings,row.subject),'status':row.status,'distance':row.distance} for row in rows],
            'notice':'Behavioral consistency is supporting evidence, not proof of identity or credential sharing.'}
