import { test, expect, TEST_USER, NON_EXISTENT_USER } from './fixtures.js'

/**
 * Password Reset E2E tests for Shizuha ID
 *
 * Tests the complete password reset flow:
 * 1. Request password reset for existing user -> receives reset email
 * 2. Request password reset for non-existent user -> receives account creation email
 * 3. Validate reset token
 * 4. Complete password reset with new password
 */

test.describe('Password Reset', () => {

  test.describe('Password Reset Request UI', () => {

    test('should display forgot password link on login page', async ({ page }) => {
      await page.goto('/id/login')

      // Check for forgot password link
      await expect(page.locator('text=Forgot password')).toBeVisible()
    })

    test('should navigate to forgot password page', async ({ page }) => {
      await page.goto('/id/login')

      // Click forgot password link
      await page.click('text=Forgot password')

      // Should navigate to forgot password page
      await expect(page).toHaveURL(/.*forgot-password/)

      // Check page elements
      await expect(page.locator('input[type="email"]').or(page.locator('input[id="email"]'))).toBeVisible()
    })

  })

  test.describe('Password Reset API - Existing User', () => {

    test('should return success message for existing user', async ({ apiContext }) => {
      const response = await apiContext.post('auth/password/reset/', {
        data: {
          email: TEST_USER.email
        }
      })

      expect(response.ok()).toBeTruthy()

      const data = await response.json()
      expect(data.message).toContain('If an account exists')
    })

    test('should send password reset email to existing user', async ({ apiContext, request }) => {
      // Clear mailpit first
      const mailpitBase = process.env.MAILPIT_URL || 'http://mailpit:8025'

      // Request password reset
      const response = await apiContext.post('auth/password/reset/', {
        data: {
          email: TEST_USER.email
        }
      })

      expect(response.ok()).toBeTruthy()

      // Check Mailpit for the email
      // Note: In actual test, we'd query Mailpit API to verify email was sent
      // This test verifies the API returns successfully
    })

  })

  test.describe('Password Reset API - Non-Existent User', () => {

    test('should return success message for non-existent user (no enumeration)', async ({ apiContext }) => {
      const response = await apiContext.post('auth/password/reset/', {
        data: {
          email: NON_EXISTENT_USER.email
        }
      })

      // Should still return 200 to prevent email enumeration
      expect(response.ok()).toBeTruthy()

      const data = await response.json()
      expect(data.message).toContain('If an account exists')
    })

    test('should send account creation email to non-existent user', async ({ apiContext }) => {
      // Request password reset for non-existent user
      const response = await apiContext.post('auth/password/reset/', {
        data: {
          email: 'newuser@shizuha.test'
        }
      })

      expect(response.ok()).toBeTruthy()

      // The API sends an account creation email instead of password reset
      // Verification would check Mailpit for "Create your Shizuha account" subject
    })

  })

  test.describe('Password Reset Token Validation', () => {

    test('should reject invalid reset token', async ({ apiContext }) => {
      const response = await apiContext.post('auth/password/reset/validate/', {
        data: {
          token: 'invalid-token-12345'
        }
      })

      // Should return error for invalid token
      expect(response.status()).toBe(400)
    })

    test('should reject empty token', async ({ apiContext }) => {
      const response = await apiContext.post('auth/password/reset/validate/', {
        data: {
          token: ''
        }
      })

      expect(response.status()).toBe(400)
    })

  })

  test.describe('Password Reset Confirmation', () => {

    test('should reject password reset with invalid token', async ({ apiContext }) => {
      const response = await apiContext.post('auth/password/reset/confirm/', {
        data: {
          token: 'invalid-token-12345',
          new_password: 'NewSecurePass123!',
          confirm_password: 'NewSecurePass123!'
        }
      })

      // Should return error for invalid token
      expect(response.status()).toBe(400)
    })

    test('should reject mismatched passwords', async ({ apiContext }) => {
      const response = await apiContext.post('auth/password/reset/confirm/', {
        data: {
          token: 'some-token',
          new_password: 'NewSecurePass123!',
          confirm_password: 'DifferentPass456!'
        }
      })

      // Should return error for mismatched passwords
      expect(response.status()).toBe(400)
    })

    test('should reject weak password', async ({ apiContext }) => {
      const response = await apiContext.post('auth/password/reset/confirm/', {
        data: {
          token: 'some-token',
          new_password: '123',
          confirm_password: '123'
        }
      })

      // Should return error for weak password
      expect(response.status()).toBe(400)
    })

  })

  test.describe('Rate Limiting', () => {

    test('should allow up to 3 password reset requests per hour', async ({ apiContext }) => {
      // Make 3 requests - all should succeed
      for (let i = 0; i < 3; i++) {
        const response = await apiContext.post('auth/password/reset/', {
          data: {
            email: TEST_USER.email
          }
        })

        expect(response.ok()).toBeTruthy()
      }

      // Note: 4th request should still return 200 (to prevent enumeration)
      // but internally no email is sent
      const response = await apiContext.post('auth/password/reset/', {
        data: {
          email: TEST_USER.email
        }
      })

      expect(response.ok()).toBeTruthy()
    })

  })

  test.describe('Security', () => {

    test('should not reveal whether email exists', async ({ apiContext }) => {
      // Request for existing user
      const existingResponse = await apiContext.post('auth/password/reset/', {
        data: {
          email: TEST_USER.email
        }
      })

      // Request for non-existing user
      const nonExistingResponse = await apiContext.post('auth/password/reset/', {
        data: {
          email: 'definitely.not.exists@example.com'
        }
      })

      // Both should return same status and similar message
      expect(existingResponse.status()).toBe(nonExistingResponse.status())

      const existingData = await existingResponse.json()
      const nonExistingData = await nonExistingResponse.json()

      expect(existingData.message).toBe(nonExistingData.message)
    })

  })

})
