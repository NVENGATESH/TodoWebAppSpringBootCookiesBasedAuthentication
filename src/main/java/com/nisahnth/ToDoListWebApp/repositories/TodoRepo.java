package com.nisahnth.ToDoListWebApp.repositories;

import com.nisahnth.ToDoListWebApp.model.TodoList;
import com.nisahnth.ToDoListWebApp.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


import java.util.List;
import java.util.Optional;


@Repository
public interface TodoRepo extends JpaRepository<TodoList,Long> {


    List<TodoList> findByOwner(User user);
}
