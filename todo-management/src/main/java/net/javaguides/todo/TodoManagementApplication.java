package net.javaguides.todo;

import org.modelmapper.ModelMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class TodoManagementApplication {
	@Bean
    public ModelMapper modelMapper(){
		return new ModelMapper();
	}
	public static void main(String[] args) {
		SpringApplication.run(TodoManagementApplication.class, args);
		Student student=new Student(1,"gopi");
		System.out.println(student.getId());
		System.out.println(student.getName());
	}

}
