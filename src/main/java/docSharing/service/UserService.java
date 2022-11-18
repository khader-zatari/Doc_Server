package docSharing.service;

import docSharing.entities.User;
import docSharing.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public User updateUserName(String email, String name) {
        User user = userRepository.findByEmail(email);

        if (user!= null) {
            user.setName(name);
            return userRepository.save(user);
        } else {
            throw new IllegalArgumentException(String.format("Email address: %s does not exist", email));
        }
    }

    public User updateUserEmail(String email, String newEmail) {
        User user = userRepository.findByEmail(email);

        if (user!= null) {
            user.setEmail(email);
            return userRepository.save(user);
        } else {
            throw new IllegalArgumentException(String.format("Email address: %s does not exist", email));
        }
    }


}
