package com.nisahnth.ToDoListWebApp.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nisahnth.ToDoListWebApp.model.AppRole;
import com.nisahnth.ToDoListWebApp.model.Role;
import com.nisahnth.ToDoListWebApp.model.TodoList;
import com.nisahnth.ToDoListWebApp.model.User;
import com.nisahnth.ToDoListWebApp.payload.TodoDto;
import com.nisahnth.ToDoListWebApp.payload.TodoDtoResponse;
import com.nisahnth.ToDoListWebApp.repositories.RoleRepository;
import com.nisahnth.ToDoListWebApp.repositories.TodoRepo;
import com.nisahnth.ToDoListWebApp.repositories.UserRepository;
import com.nisahnth.ToDoListWebApp.security.request.LoginRequest;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.time.LocalDate;
import java.time.format.TextStyle;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Service
public class TodoServiceImp implements ToDoService {

    @Autowired
    private  final TodoRepo repo;
    @Autowired
    private   RoleRepository roleRepository;

    @Autowired
    private UserRepository userRepository;

@Autowired
private ModelMapper modelMapper;


    public TodoServiceImp(TodoRepo repo) {
        this.repo = repo;

    }

    public static String getTodayDate(){
        LocalDate today = LocalDate.now();

        // Date (YYYY-MM-DD)
        String currentDate = today.toString();


        return currentDate;
    }
    public static String getTodayDay(){
        LocalDate today = LocalDate.now();



        // Day name (Monday, Tuesday...)
        String dayName = today.getDayOfWeek().getDisplayName(TextStyle.FULL, Locale.ENGLISH);

        return dayName;
    }
//
//    @Override
//    public List<TodoList> getAlltodo() {
//
//        List<TodoList> todolist=repo.findAll();
//        return todolist.stream()
//                .map(todo -> modelMapper.map(todo, TodoDtoResponse.class))
//                .toList();
//
//        return   modelMapper.map(todolist, TodoDtoResponse.class);;
//    }

    @Override
    public TodoDtoResponse getAlltodo() {
        List<TodoList> todolist=repo.findAll();

        return modelMapper.map(todolist, TodoDtoResponse.class);
    }


    public TodoDto create(TodoDto todoList, Principal principal) {

        TodoList todoList1=modelMapper.map(todoList,TodoList.class);
        // Get logged-in username
        String username = principal.getName();

        // Fetch user from DB
        User owner = userRepository.findByUserName(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Attach the owner
        todoList1.setOwner(owner);



        todoList1.setDay(getTodayDay());
        todoList1.setDate(getTodayDate());
        repo.save(todoList1);
        // Save
        TodoDto todoDto=modelMapper.map(todoList1, TodoDto.class);

        return todoDto;
    }

    public List<TodoList> getTodosByUsername(String username) {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Fetch all todos owned by this user
        // Fetch all todos owned by this user
        List<TodoList> todoLists = repo.findByOwner(user);

        return todoLists;
    }

    @Override
    public List<User> getAllUserInfo() {
        return  userRepository.findAll();
    }

    @Override
    public String deleteTodo(Long id) {
        TodoList list=repo.findById(id).orElseThrow( ()->new RuntimeException("User not found"));
      repo.delete(list);
        return "Successfully deleted";
    }

    @Override
    public String chagetodo(Long id, TodoDto updatedTodo) {

        TodoList existingTodo = repo.findById(id)
                .orElseThrow(() -> new RuntimeException("Todo not found"));
        TodoList list=modelMapper.map(updatedTodo,TodoList.class);


        existingTodo.setTitle(list.getTitle());
        existingTodo.setCompleted(list.isCompleted());



         repo.save(existingTodo);
        return "Successfully updated";
    }

    @Override
    public String changecompletedtodo(Long id) {
        TodoList existingTodo = repo.findById(id)
                .orElseThrow(() -> new RuntimeException("Todo not found"));


        existingTodo.setCompleted(!existingTodo.isCompleted());

        repo.save(existingTodo);
        return "Successfully updated";
    }

    @Override
    public String changeadmin(LoginRequest loginRequest) {
        User user = userRepository.findByUserName(loginRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        Role adminRole = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                .orElseThrow(() -> new RuntimeException("Role not found"));


        Set<Role> roles = new HashSet<>(user.getRoles());
        roles.add(adminRole);

        user.setRoles(roles);
        userRepository.save(user);

        return "Successfully added ROLE_ADMIN to " + loginRequest.getUsername();
    }

}
