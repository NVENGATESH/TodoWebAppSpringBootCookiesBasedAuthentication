package com.nisahnth.ToDoListWebApp.controller;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.nisahnth.ToDoListWebApp.model.TodoList;
import com.nisahnth.ToDoListWebApp.model.User;
import com.nisahnth.ToDoListWebApp.payload.TodoDto;
import com.nisahnth.ToDoListWebApp.payload.TodoDtoResponse;
import com.nisahnth.ToDoListWebApp.repositories.UserRepository;
import com.nisahnth.ToDoListWebApp.security.request.LoginRequest;
import com.nisahnth.ToDoListWebApp.service.ToDoService;
import com.nisahnth.ToDoListWebApp.service.TodoServiceImp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.web.bind.annotation.*;


import java.security.Principal;
import java.util.List;

@CrossOrigin("http://localhost:5173")
@RestController
@RequestMapping("/api")
public class TodoController {


    @Autowired
 private final ToDoService service;

    @Autowired
    private UserRepository userRepository;


    public TodoController(TodoServiceImp service) {
        this.service = service;
    }

    @GetMapping("/public/hello")
    public String getall(){

        return  "Hello";
    }

    @PreAuthorize("hasRole('ADMIN')")
  @GetMapping("/admin/hello")
    public String getAdmin(){

        return  "Hello adimin";
    }

    @GetMapping("/public/todoall")
    public ResponseEntity<TodoDtoResponse>getAllToDoInfo(){

        TodoDtoResponse response = service.getAlltodo();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }



    @PostMapping("/public/todo")
    public TodoDto createTodo(@RequestBody TodoDto todoList, Principal principal) {
        return service.create(todoList, principal);
    }

    @GetMapping("/public/todos")
    public List<TodoList> getCurrentUserTodos(Principal principal) {
        String username = principal.getName();
        return service.getTodosByUsername(username);
    }


    @GetMapping("/public/findAlluser")
    public List<User> getAllUserInfo( ) {

        return service.getAllUserInfo();
    }

    @DeleteMapping("/public/deleteByidTodo/{id}")
    public String deletetodoByid(@PathVariable Long id){
        return  service.deleteTodo(id);

    }

    @PutMapping("/public/updattobyid/{id}")
    public String chageTodo(@RequestBody TodoDto list,@PathVariable Long id){
        return  service.chagetodo(id,list);

    }

    @PutMapping("/public/completed/{id}")
    public String changecompleted(@PathVariable Long id){
        return  service.changecompletedtodo(id);

    }

    @PostMapping("/public/changeAdmin")
    public String changeAdmin(@RequestBody LoginRequest loginRequest){
        return  service.changeadmin(loginRequest);

    }

}
