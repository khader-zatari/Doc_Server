package docSharing.controller;

import docSharing.DTO.FS.PermissionDTO;
import docSharing.DTO.Doc.UpdateDocContentRes;
import docSharing.Utils.Validation;
import docSharing.entities.Document;
import docSharing.entities.Permission;
import docSharing.entities.UserRole;
import docSharing.response.PermissionResponse;
import docSharing.response.Response;
import docSharing.service.DocService;
import docSharing.DTO.Doc.ChangeRoleDTO;
import docSharing.DTO.Doc.CurrentViewingUserDTO;
import docSharing.DTO.Doc.ManipulatedTextDTO;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;


import java.util.List;
import java.util.Optional;


@RequestMapping("/doc")
@CrossOrigin
@RestController
public class DocController {
    @Autowired
    DocService docService;

    private static final Logger logger = LogManager.getLogger(DocController.class.getName());

    /**
     * @param docId              document id
     * @param manipulatedTextDTO the change in the text
     * @return the changed content to all subscribed users
     */
    @MessageMapping("/update/{docId}")
    @SendTo("/topic/updates/{docId}")
    public UpdateDocContentRes sendUpdatedText(@DestinationVariable Long docId, ManipulatedTextDTO manipulatedTextDTO) {

        logger.info("start sendUpdatedText function");
        logger.info("validate docId param");
        Validation.nullCheck(docId);
        logger.info("validate manipulatedTextDTO param");
        Validation.nullCheck(manipulatedTextDTO);

        return docService.UpdateDocContent(docId, manipulatedTextDTO);
    }


    /**
     * @param docId document id
     * @return Document OBJ
     */
    @RequestMapping(value = "/{docId}", method = RequestMethod.GET)
    public ResponseEntity<Response<Document>> getDocument(@PathVariable Long docId) {
        logger.info("start getDocument function");
        logger.info("validate docId param");
        Validation.nullCheck(docId);

        Document document;
        try {
            document = docService.getDocument(docId);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Response.failure(e.getMessage()));
        }

        return ResponseEntity.status(HttpStatus.OK).body(Response.success(document));
    }


    /**
     * @param docId document Id
     * @param user  Current Viewing User userName
     * @return the list of all the current viewing user to the document
     */
    @MessageMapping("/join/{docId}")
    @SendTo("/topic/usersJoin/{docId}")
    public List<String> sendNewUserJoinMessage(@DestinationVariable Long docId, CurrentViewingUserDTO user) {

        logger.info("start sendNewUserJoinMessage function");
        logger.info("validate docId param");
        Validation.nullCheck(docId);
        logger.info("validate User param");
        Validation.nullCheck(user);

        return docService.addUserToViewingUsers(docId, user.userName);
    }


    /**
     * @param docId document Id
     * @param user  Current Viewing User userName
     * @return the list of all the current viewing user to the document
     */
    @MessageMapping("/userDisconnect/{docId}")
    @SendTo("/topic/userDisconnect/{docId}")
    public List<String> removeUserFromViewingUsers(@DestinationVariable Long docId, CurrentViewingUserDTO user) {

        logger.info("start sendNewUserJoinMessage function");
        logger.info("validate docId param");
        Validation.nullCheck(docId);
        logger.info("validate User param");
        Validation.nullCheck(user);
        Validation.nullCheck(user.userName);

        return docService.removeUserFromViewingUsers(docId, user.userName);

    }


    /**
     * @param permissionDTO usersId  and DocId
     * @return response Entity of the userRole
     */
    @RequestMapping(value = "getPerm", method = RequestMethod.POST)
    public ResponseEntity<Response<PermissionResponse>> getPermission(@RequestBody PermissionDTO permissionDTO) {

        logger.info("start getPerm Function");
        logger.info("validate permission param");
        Validation.nullCheck(permissionDTO);
        Validation.nullCheck(permissionDTO.docId);
        Validation.nullCheck(permissionDTO.userId);

        Optional<Permission> optionalPer = docService.getPermission(permissionDTO.userId, permissionDTO.docId);
        if (!optionalPer.isPresent()) {
            return ResponseEntity.badRequest().body(Response.failure("You have no Access to this file"));
        }
        UserRole userRole = optionalPer.get().getUserRole();

        return ResponseEntity.ok(Response.success(new PermissionResponse(userRole)));
    }


    /**
     * @param docId         document Id
     * @param changeRoleDTO Param to change the role of user
     * @return if the change is done or note
     */
    @RequestMapping(value = "changeUserRoll/{docId}", method = RequestMethod.POST)
    public ResponseEntity<Response<PermissionResponse>> changeUserRole(@PathVariable Long docId, @RequestBody ChangeRoleDTO changeRoleDTO) {

        logger.info("start changeUserRollInDoc function");
        logger.info("validate docId param");
        Validation.nullCheck(docId);
        logger.info("validate ChnageRoleDTO param");
        Validation.nullCheck(changeRoleDTO);
//        Validation.nullCheck(changeRoleDTO.userRole);
        Validation.nullCheck(changeRoleDTO.ownerId);
        Validation.nullCheck(changeRoleDTO.email);
        Validation.nullCheck(changeRoleDTO.isDelete);

        UserRole userRole;
        try {
            userRole = docService.editRole(docId, changeRoleDTO.ownerId, changeRoleDTO.email, changeRoleDTO.userRole, changeRoleDTO.isDelete);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Response.failure(e.getMessage()));
        }

        return ResponseEntity.status(HttpStatus.OK).body(Response.success(new PermissionResponse(userRole)));
    }

}