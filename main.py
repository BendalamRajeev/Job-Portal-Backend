from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import uuid
import os
from sqlalchemy import create_engine, Column, String, Text, DateTime, ForeignKey, ARRAY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from dotenv import load_dotenv
from passlib.context import CryptContext
import jwt
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Security
from fastapi.staticfiles import StaticFiles

# Load environment variables
load_dotenv()

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL")

print("DATABASE_URL:", DATABASE_URL)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="Job Beacon API")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "resumes"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app.mount("/resumes", StaticFiles(directory=UPLOAD_DIR), name="resumes")

# Database models
class UserModel(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True)
    email = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False)  # 'jobseeker', 'employer', 'admin'
    created_at = Column(DateTime, nullable=False)
    name = Column(String, nullable=True)
    company = Column(String, nullable=True)

class JobModel(Base):
    __tablename__ = "jobs"
    
    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    location = Column(String, nullable=False)
    employer_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False)
    company_name = Column(String, nullable=True)
    job_type = Column(String, nullable=True)
    salary = Column(String, nullable=True)
    skills = Column(ARRAY(String), nullable=False)

class ApplicationModel(Base):
    __tablename__ = "applications"
    
    id = Column(String, primary_key=True)
    job_id = Column(String, ForeignKey("jobs.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    resume_url = Column(String, nullable=False)
    status = Column(String, nullable=False)
    applied_at = Column(DateTime, nullable=False)
    cover_letter = Column(Text, nullable=True)
    applicant_name = Column(String, nullable=True)
    job_title = Column(String, nullable=True)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# API Models
class UserRole(str):
    JOBSEEKER = "jobseeker"
    EMPLOYER = "employer"
    ADMIN = "admin"

class ApplicationStatus(str):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"

# User models
class UserBase(BaseModel):
    email: str
    role: str
    name: Optional[str] = None
    company: Optional[str] = None

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: str
    createdAt: datetime
    
    class Config:
        orm_mode = True

# Job models
class JobBase(BaseModel):
    title: str
    description: str
    location: str
    employerId: str
    skills: List[str]
    companyName: Optional[str] = None
    jobType: Optional[str] = None
    salary: Optional[str] = None

class JobCreate(JobBase):
    pass

class Job(JobBase):
    id: str
    createdAt: datetime
    
    class Config:
        orm_mode = True

# Application models
class ApplicationBase(BaseModel):
    jobId: str
    userId: str
    resumeUrl: str
    coverLetter: Optional[str] = None
    applicantName: Optional[str] = None
    jobTitle: Optional[str] = None

class ApplicationCreate(ApplicationBase):
    pass

class Application(ApplicationBase):
    id: str
    status: str
    appliedAt: datetime
    
    class Config:
        orm_mode = True

class StatusUpdate(BaseModel):
    status: str
# Helper functions to convert between DB models and Pydantic models
def db_to_user(db_user):
    return {
        "id": str(db_user.id),
        "email": db_user.email,
        "role": db_user.role,
        "createdAt": db_user.created_at,
        "name": db_user.name,
        "company": db_user.company
    }

def db_to_job(db_job):
    return {
        "id": str(db_job.id),
        "title": db_job.title,
        "description": db_job.description,
        "location": db_job.location,
        "employerId": str(db_job.employer_id),
        "createdAt": db_job.created_at,
        "companyName": db_job.company_name,
        "jobType": db_job.job_type,
        "salary": db_job.salary,
        "skills": db_job.skills
    }

def db_to_application(db_app):
    return {
        "id": str(db_app.id),
        "jobId": str(db_app.job_id),
        "userId": str(db_app.user_id),
        "resumeUrl": db_app.resume_url,
        "status": db_app.status,
        "appliedAt": db_app.applied_at,
        "coverLetter": db_app.cover_letter,
        "applicantName": db_app.applicant_name,
        "jobTitle": db_app.job_title
    }

# API Endpoints
@app.get("/")
def read_root():
    return {"message": "Welcome to Job Beacon API"}

# User endpoints
@app.get("/users", response_model=List[User])
def get_users(db: Session = Depends(get_db)):
    db_users = db.query(UserModel).all()
    return [db_to_user(user) for user in db_users]

@app.get("/users/{user_id}", response_model=User)
def get_user(user_id: str, db: Session = Depends(get_db)):
    db_user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_to_user(db_user)

@app.get("/users/role/{role}", response_model=List[User])
def get_users_by_role(role: str, db: Session = Depends(get_db)):
    if role not in [UserRole.JOBSEEKER, UserRole.EMPLOYER, UserRole.ADMIN]:
        raise HTTPException(status_code=400, detail="Invalid role")
    db_users = db.query(UserModel).filter(UserModel.role == role).all()
    return [db_to_user(user) for user in db_users]

# Job endpoints
@app.get("/jobs", response_model=List[Job])
def get_jobs(db: Session = Depends(get_db)):
    db_jobs = db.query(JobModel).all()
    return [db_to_job(job) for job in db_jobs]

@app.get("/jobs/{job_id}", response_model=Job)
def get_job(job_id: str, db: Session = Depends(get_db)):
    db_job = db.query(JobModel).filter(JobModel.id == job_id).first()
    if not db_job:
        raise HTTPException(status_code=404, detail="Job not found")
    return db_to_job(db_job)

@app.get("/jobs/employer/{employer_id}", response_model=List[Job])
def get_employer_jobs(employer_id: str, db: Session = Depends(get_db)):
    db_jobs = db.query(JobModel).filter(JobModel.employer_id == employer_id).all()
    return [db_to_job(job) for job in db_jobs]

@app.post("/jobs", response_model=Job, status_code=status.HTTP_201_CREATED)
def create_job(job: JobCreate, db: Session = Depends(get_db)):
    job_id = str(uuid.uuid4())
    db_job = JobModel(
        id=job_id,
        title=job.title,
        description=job.description,
        location=job.location,
        employer_id=job.employerId,
        created_at=datetime.now(),
        company_name=job.companyName,
        job_type=job.jobType,
        salary=job.salary,
        skills=job.skills
    )
    
    db.add(db_job)
    db.commit()
    db.refresh(db_job)
    
    return db_to_job(db_job)

# Application endpoints
@app.get("/applications", response_model=List[Application])
def get_applications(db: Session = Depends(get_db)):
    db_applications = db.query(ApplicationModel).all()
    return [db_to_application(app) for app in db_applications]

@app.get("/applications/user/{user_id}", response_model=List[Application])
def get_user_applications(user_id: str, db: Session = Depends(get_db)):
    db_applications = db.query(ApplicationModel).filter(ApplicationModel.user_id == user_id).all()
    return [db_to_application(app) for app in db_applications]

@app.get("/applications/job/{job_id}", response_model=List[Application])
def get_job_applications(job_id: str, db: Session = Depends(get_db)):
    db_applications = db.query(ApplicationModel).filter(ApplicationModel.job_id == job_id).all()
    return [db_to_application(app) for app in db_applications]

@app.get("/applications/{application_id}", response_model=Application)
def get_application(application_id: str, db: Session = Depends(get_db)):
    db_application = db.query(ApplicationModel).filter(ApplicationModel.id == application_id).first()
    if not db_application:
        raise HTTPException(status_code=404, detail="Application not found")
    return db_to_application(db_application)

@app.post("/applications", response_model=Application, status_code=status.HTTP_201_CREATED)
def create_application(application: ApplicationCreate, db: Session = Depends(get_db)):
    application_id = str(uuid.uuid4())
    db_application = ApplicationModel(
        id=application_id,
        job_id=application.jobId,
        user_id=application.userId,
        resume_url=application.resumeUrl,
        status=ApplicationStatus.PENDING,
        applied_at=datetime.now(),
        cover_letter=application.coverLetter,
        applicant_name=application.applicantName,
        job_title=application.jobTitle
    )
    
    db.add(db_application)
    db.commit()
    db.refresh(db_application)
    
    return db_to_application(db_application)

@app.put("/applications/{application_id}/status", response_model=Application)
def update_application_status(application_id: str, status_update: StatusUpdate, db: Session = Depends(get_db)):
    status = status_update.status
    if status not in [ApplicationStatus.PENDING, ApplicationStatus.ACCEPTED, ApplicationStatus.REJECTED]:
        raise HTTPException(status_code=400, detail="Invalid status")
    db_application = db.query(ApplicationModel).filter(ApplicationModel.id == application_id).first()
    if not db_application:
        raise HTTPException(status_code=404, detail="Application not found")
    db_application.status = status
    db.commit()
    db.refresh(db_application)
    return db_to_application(db_application)

@app.delete("/applications/{application_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_application(application_id: str, db: Session = Depends(get_db)):
    db_application = db.query(ApplicationModel).filter(ApplicationModel.id == application_id).first()
    if not db_application:
        raise HTTPException(status_code=404, detail="Application not found")
    
    db.delete(db_application)
    db.commit()
    return

# Create tables on startup
@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)

SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

@app.post("/auth/register", response_model=User)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(UserModel).filter(UserModel.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    db_user = UserModel(
        id=user_id,
        email=user.email,
        password_hash=hash_password(user.password),
        role=user.role,
        created_at=datetime.now(),
        name=user.name,
        company=user.company
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_to_user(db_user)

@app.post("/auth/login", response_model=Token)
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    db_user = db.query(UserModel).filter(UserModel.email == form_data.username).first()
    if not db_user or not verify_password(form_data.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    user_data = db_to_user(db_user)
    token_data = {"sub": str(db_user.id), "email": db_user.email, "role": db_user.role}
    access_token = create_access_token(token_data)
    return {"access_token": access_token, "token_type": "bearer", "user": user_data}

@app.post("/upload-resume/")
async def upload_resume(file: UploadFile = File(...)):
    file_location = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_location, "wb") as buffer:
        buffer.write(await file.read())
    return {"resume_url": f"/resumes/{file.filename}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=9000, reload=True)
