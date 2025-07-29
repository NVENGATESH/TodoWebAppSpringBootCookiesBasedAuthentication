package com.nisahnth.ToDoListWebApp.model;


import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class TodoList {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private  Long id;
    private String title;
    private String description;
    private boolean completed;
    private String date ;
    private String day;



    @ManyToOne
    @JoinColumn(name = "owner_id")
    @JsonBackReference  //ithu multiple time json object vantha thavirkum
    private User owner;

}
