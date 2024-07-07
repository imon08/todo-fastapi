from typing import Annotated
from fastapi.exception_handlers import http_exception_handler
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException, Path
from models import Todos
from database import SessionLocal
from starlette import status
from .auth import get_current_user


router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


class TododRequest(BaseModel):
    title: str = Field(min_length=3)
    description: str = Field(min_length=3, max_length=100)
    priority: int = Field(gt=0, lt=6)
    complete: bool


@router.get("/", status_code=status.HTTP_200_OK)
async def read_all(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=402, detail="Authentication failed")
    return db.query(Todos).filter(Todos.owner_id == user.get("id")).all()


@router.get("/todo/{todo_id}", status_code=status.HTTP_200_OK)
async def read_todo_id(
    user: user_dependency, db: db_dependency, todo_id: int = Path(gt=0)
):
    if user is None:
        raise HTTPException(status_code=402, detail="Authentication failed")
    todo_model = (
        db.query(Todos)
        .filter(Todos.id == todo_id)
        .filter(Todos.owner_id == user.get("id"))
        .first()
    )
    if todo_model is None:
        raise HTTPException(status_code=404, detail="Todo id not found")
    return todo_model


@router.post("/todo", status_code=status.HTTP_200_OK)
async def create_todo(
    user: user_dependency, db: db_dependency, todo_request: TododRequest
):
    if user is None:
        raise HTTPException(status_code=402, detail="Authentication failed")

    todo_model = Todos(**todo_request.model_dump(), owner_id=user.get("id"))
    db.add(todo_model)
    db.commit()


@router.put("/todo/{todo_id}", status_code=status.HTTP_204_NO_CONTENT)
async def update_todo(
    user: user_dependency,
    db: db_dependency,
    todo_request: TododRequest,
    todo_id: int = Path(gt=0),
):
    if user is None:
        raise HTTPException(status_code=402, detail="Authentication failed")

    todo_model = (
        db.query(Todos)
        .filter(Todos.owner_id == user.get("id"))
        .filter(Todos.id == todo_id)
        .first()
    )
    if todo_model is None:
        raise HTTPException(status_code=404, detail="Todo not found")

    todo_model.title = todo_request.title
    todo_model.description = todo_request.description
    todo_model.priority = todo_request.priority
    todo_model.complete = todo_request.complete
    db.add(todo_model)
    db.commit()


@router.delete("/todo/{todo_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_todo(
    user: user_dependency, db: db_dependency, todo_id: int = Path(gt=0)
):
    if user is None:
        raise HTTPException(status_code=402, detail="Authentication failed")
    todo_model = (
        db.query(Todos)
        .filter(Todos.owner_id == user.get("id"))
        .filter(Todos.id == todo_id)
        .first()
    )
    if todo_model is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    usermodel = (
        db.query(Todos)
        .filter(Todos.owner_id == user.get("id"))
        .filter(Todos.id == todo_id)
    )
    if usermodel is None:
        return "None"
    db.query(Todos).filter(Todos.owner_id == user.get("id")).filter(
        Todos.id == todo_id
    ).delete()
    db.commit()
