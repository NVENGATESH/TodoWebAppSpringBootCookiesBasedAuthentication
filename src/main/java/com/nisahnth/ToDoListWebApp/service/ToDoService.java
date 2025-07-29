package com.nisahnth.ToDoListWebApp.service;

import com.nisahnth.ToDoListWebApp.model.TodoList;
import com.nisahnth.ToDoListWebApp.model.User;
import com.nisahnth.ToDoListWebApp.payload.TodoDto;
import com.nisahnth.ToDoListWebApp.payload.TodoDtoResponse;
import com.nisahnth.ToDoListWebApp.security.request.LoginRequest;

import java.security.Principal;
import java.util.List;

public interface ToDoService {


    TodoDtoResponse getAlltodo();


    TodoDto create(TodoDto todoList, Principal principal);

    List<TodoList> getTodosByUsername(String username);

    List<User> getAllUserInfo();

    String deleteTodo(Long id);

    String chagetodo(Long id, TodoDto list);

    String changecompletedtodo(Long id);

    String changeadmin(LoginRequest loginRequest);
}
