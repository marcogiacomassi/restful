<?php

/**
 * @file
 * Contains RestfulTokenAuth.
 */

class RestfulTokenAuthentication extends \RestfulEntityBase {

  /**
   * Overrides RestfulEntityBase::getQueryForList().
   *
   * Keep only the "token" property.
   */
  public function getPublicFields() {
    $public_fields['access_token'] = array(
      'property' => 'token',
    );
    return $public_fields;
  }

  /**
   * Overrides \RestfulEntityBase::controllers
   *
   * @var array
   */
  protected $controllers = array(
    '' => array(
      // Get or create a new token.
      'get' => 'getOrCreateToken',
    ),
  );

  /**
   * Create a token for a user, and return its value.
   */
  public function getOrCreateToken($request = NULL, stdClass $account = NULL) {
    // Check if there is a token that did not expire yet.
    $query = new EntityFieldQuery();
    $result = $query
      ->entityCondition('entity_type', $this->entityType)
      ->propertyCondition('uid', $account->uid)
      ->range(0, 1)
      ->execute();

    $token_exists = FALSE;

    if (!empty($result['restful_token_auth'])) {
      $id = key($result['restful_token_auth']);
      $auth_token = entity_load_single('restful_token_auth', $id);

      if (!empty($auth_token->expire) && $auth_token->expire < REQUEST_TIME) {
        if (variable_get('restful_token_auth_delete_expired_tokens', TRUE)) {
          // Token has expired, so we can delete this token.
          $auth_token->delete();
        }

        $token_exists = FALSE;
      }
      else {
        $token_exists = TRUE;
      }
    }

    if (!$token_exists) {
      // Create a new token.
      $values = array(
        'uid' => $account->uid,
        'type' => 'restful_token_auth',
        'created' => REQUEST_TIME,
        'name' => 'self',
        'token' => md5(time()),
      );
      $auth_token = entity_create('restful_token_auth', $values);
      entity_save('restful_token_auth', $auth_token);
      $id = $auth_token->id;
    }

    return $this->viewEntity($id, $request, $account);
  }

  /**
   * Set HTTP access control (CORS) for the request.
   */
  public function setCors() {
    if (!variable_get('restful_token_auth_set_cors', TRUE)) {
      return;
    }

    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Headers: Authorization');
  }
}
