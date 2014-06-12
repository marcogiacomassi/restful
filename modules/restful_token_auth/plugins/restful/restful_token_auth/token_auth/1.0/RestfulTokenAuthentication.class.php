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
    // Login the user.
    $this->loginUser($account);

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
   * If a user is not logged in, log them in.
   *
   * Even though this plugin returns a token, it is possible that the
   * implementing module would like also the get cookies back.
   *
   * @param $account
   *   The user object that was retrieved by the \RestfulAuthenticationManager.
   */
  public function loginUser($account) {
    if (!variable_get('restful_token_auth_login_user', TRUE)) {
      return;
    }

    global $user;
    if ($user->uid) {
      // User is already logged in, which means they probably autenticated using
      // cookies.
      return;
    }

    $user = user_load($account->uid);

    $login_array = array ('name' => $account->name);
    user_login_finalize($login_array);
  }
}
