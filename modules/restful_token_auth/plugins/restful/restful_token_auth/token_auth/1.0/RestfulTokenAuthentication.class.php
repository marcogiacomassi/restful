<?php

/**
 * @file
 * Contains RestfulTokenAuth.
 */

class RestfulTokenAuthentication extends \RestfulEntityBase {

  /**
   * Overrides RestfulEntityBase::getPublicFields().
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
      \RestfulInterface::GET => 'getOrCreateToken',
    ),
  );

  /**
   * Create a token for a user, and return its value.
   */
  public function getOrCreateToken() {
    $account = $this->getAccount();
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
        'token' => drupal_random_key(),
      );
      
      // Add expire configuration variable.
      if (variable_get('restful_token_auth_expire_time', FALSE)) {
        // Accepted strtotime formats : +1 day, +1 week, + 1 month.
        $expire = strtotime(variable_get('restful_token_auth_expire_time', FALSE));
        $values['expire'] = $expire;
      }
      
      $auth_token = entity_create('restful_token_auth', $values);
      entity_save('restful_token_auth', $auth_token);
      $id = $auth_token->id;
    }

    return $this->viewEntity($id);
  }
}
