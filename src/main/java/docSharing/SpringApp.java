package docSharing;

import docSharing.entities.INode;
import docSharing.entities.INodeType;
import docSharing.repository.FileSystemRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.time.LocalDate;
import java.time.LocalDateTime;

@SpringBootApplication
public class SpringApp {
    public static void main(String[] args) {
        SpringApplication.run(SpringApp.class, args);
    }

    @Bean
    public CommandLineRunner initData(FileSystemRepository fsRepository) {
        return args -> {
            if (!fsRepository.existsById(1L)) {
                fsRepository.save(new INode("root", INodeType.DIR, LocalDateTime.now(), null, null));
            }
        };
    }
}