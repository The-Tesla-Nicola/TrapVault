export interface User {
  id: string | number;
  username: string;
  email?: string;
  name?: string;
  account?: string;
  role?: string;
}

export interface AuthResponse {
  status: string;
  message: string;
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  user: User;
  redirect?: string;
  mfa_required?: boolean;
}

export interface Transaction {
  id: string;
  date: string;
  description: string;
  amount: number;
  type: 'debit' | 'credit';
  status: 'completed' | 'pending' | 'processing';
  category?: string;
}

export interface Account {
  id: string;
  name: string;
  number: string;
  balance: number;
  type: 'checking' | 'savings' | 'investment';
  currency: string;
}
