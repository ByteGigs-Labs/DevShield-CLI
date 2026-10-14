package com.example;

public class UserRepository {
    public Object find(String name) {
        return em.createQuery("from User where name = '" + name + "'").getResultList();
    }
}
