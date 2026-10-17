import { test as base } from '@playwright/test'

/**
 * Test fixtures for Shizuha ID E2E tests
 * Provides test user context and utilities
 */

// Test user credentials - must exist in the database
export const TEST_USER = {
  username: 'testuser',
  password: 'TestPass123',
  email: 'testuser@example.com'
}

// Non-existent user for testing account creation flow
export const NON_EXISTENT_USER = {
  email: 'nonexistent@example.com'
}

// Mailpit API helper
export const MAILPIT = {
  baseUrl: process.env.MAILPIT_URL || 'http://mailpit:8025',

  // Get messages from Mailpit
  async getMessages(apiContext) {
    const response = await apiContext.get(`${this.baseUrl}/mailpit/api/v1/messages`)
    if (!response.ok()) {
      throw new Error(`Failed to fetch messages: ${response.status()}`)
    }
    return response.json()
  },

  // Find message by recipient email
  async findMessageByRecipient(apiContext, email) {
    const data = await this.getMessages(apiContext)
    return data.messages.find(msg =>
      msg.To.some(to => to.Address.toLowerCase() === email.toLowerCase())
    )
  },

  // Get message content
  async getMessageContent(apiContext, messageId) {
    const response = await apiContext.get(`${this.baseUrl}/mailpit/api/v1/message/${messageId}`)
    if (!response.ok()) {
      throw new Error(`Failed to fetch message: ${response.status()}`)
    }
    return response.json()
  },

  // Delete all messages (cleanup)
  async deleteAllMessages(apiContext) {
    await apiContext.delete(`${this.baseUrl}/mailpit/api/v1/messages`)
  }
}

// Extend base test with fixtures
export const test = base.extend({
  // API context for direct API testing
  apiContext: async ({ playwright }, use) => {
    const baseUrl = process.env.BASE_URL || 'http://shizuha-nginx'
    const apiContext = await playwright.request.newContext({
      baseURL: `${baseUrl}/id/api/`,
      extraHTTPHeaders: {
        'Content-Type': 'application/json',
      },
    })

    await use(apiContext)
    await apiContext.dispose()
  },

  // Mailpit API context
  mailpitContext: async ({ playwright }, use) => {
    const mailpitUrl = process.env.MAILPIT_URL || 'http://mailpit:8025'
    const mailpitContext = await playwright.request.newContext({
      baseURL: mailpitUrl,
      extraHTTPHeaders: {
        'Content-Type': 'application/json',
      },
    })

    await use(mailpitContext)
    await mailpitContext.dispose()
  },

  // Authenticated page fixture
  authenticatedPage: async ({ page }, use) => {
    // Go to login page
    await page.goto('/id/login')

    // Wait for form to be ready
    await page.waitForSelector('input[id="username"]')

    // Fill in credentials
    await page.fill('input[id="username"]', TEST_USER.username)
    await page.fill('input[id="password"]', TEST_USER.password)

    // Click submit
    await page.click('button[type="submit"]')

    // Wait for successful login
    await page.waitForResponse(
      response => response.url().includes('/auth/login/') && response.ok(),
      { timeout: 10000 }
    )

    await use(page)
  },
})

export { expect } from '@playwright/test'
